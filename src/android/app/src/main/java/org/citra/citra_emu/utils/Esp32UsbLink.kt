// Copyright 2026 Azahar Emulator Project
// Licensed under GPLv2 or any later version
// Refer to the license.txt file included.

package org.citra.citra_emu.utils

import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.hardware.usb.UsbConstants
import android.hardware.usb.UsbDevice
import android.hardware.usb.UsbDeviceConnection
import android.hardware.usb.UsbEndpoint
import android.hardware.usb.UsbInterface
import android.hardware.usb.UsbManager
import android.os.Build
import androidx.core.content.ContextCompat
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import org.citra.citra_emu.CitraApplication

/**
 * CDC-ACM serial link to the ESP32-S3 running firmware/esp32-uds-bridge (its native USB
 * Serial/JTAG port). The core's monitor thread reaches [open], [read] and [write] through JNI
 * (jni/esp32_usb_serial.cpp); the rest of the app only calls [install] and [ensurePermission].
 */
object Esp32UsbLink {
    private const val VID_ESPRESSIF = 0x303A
    private const val PID_USB_JTAG = 0x1001
    private const val ACTION_USB_PERMISSION = "org.azahar_emu.azahar.USB_PERMISSION"

    private val lock = Any()
    private var connection: UsbDeviceConnection? = null
    private var controlInterface: UsbInterface? = null
    private var dataInterface: UsbInterface? = null
    private var outEndpoint: UsbEndpoint? = null

    @Volatile
    private var isOpen = false
    private val received = LinkedBlockingQueue<ByteArray>()
    private var pending: ByteArray? = null
    private var pendingOffset = 0
    private var installed = false

    @JvmStatic
    external fun nativeInstall()

    /** Registers this link with the core so a game's local wireless can find the board. */
    @Synchronized
    fun install() {
        if (!installed) {
            nativeInstall()
            installed = true
        }
    }

    private fun findDevice(manager: UsbManager): UsbDevice? =
        manager.deviceList.values.firstOrNull {
            it.vendorId == VID_ESPRESSIF && it.productId == PID_USB_JTAG
        }

    /**
     * Asks Android for permission to use the board if it is attached and permission is missing.
     * Returns true if the board is attached and already permitted.
     */
    fun ensurePermission(context: Context): Boolean {
        val manager = context.getSystemService(Context.USB_SERVICE) as UsbManager
        val device = findDevice(manager) ?: return false
        if (manager.hasPermission(device)) {
            return true
        }
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(receiverContext: Context, intent: Intent) {
                receiverContext.unregisterReceiver(this)
                val granted = manager.hasPermission(device)
                Log.info("ESP32 USB permission ${if (granted) "granted" else "denied"}")
            }
        }
        ContextCompat.registerReceiver(
            context,
            receiver,
            IntentFilter(ACTION_USB_PERMISSION),
            ContextCompat.RECEIVER_NOT_EXPORTED
        )
        // The intent must be explicit and the PendingIntent mutable: the system fills in the
        // device.
        val flags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            PendingIntent.FLAG_MUTABLE
        } else {
            0
        }
        val intent = Intent(ACTION_USB_PERMISSION).setPackage(context.packageName)
        manager.requestPermission(device, PendingIntent.getBroadcast(context, 0, intent, flags))
        return false
    }

    // ---- called from native (the core's monitor thread) ----

    /** Claims the board and starts the reader. False if it is absent or not permitted. */
    @JvmStatic
    fun open(): Boolean = synchronized(lock) { openLocked() }

    private fun openLocked(): Boolean {
        close()
        val manager =
            CitraApplication.appContext.getSystemService(Context.USB_SERVICE) as UsbManager
        val device = findDevice(manager)
        if (device == null) {
            Log.warning("ESP32: no board attached")
            return false
        }
        if (!manager.hasPermission(device)) {
            Log.warning("ESP32: USB permission not granted")
            return false
        }

        var comm: UsbInterface? = null
        var data: UsbInterface? = null
        for (i in 0 until device.interfaceCount) {
            val intf = device.getInterface(i)
            if (intf.interfaceClass == UsbConstants.USB_CLASS_COMM && comm == null) {
                comm = intf
            } else if (intf.interfaceClass == UsbConstants.USB_CLASS_CDC_DATA && data == null) {
                data = intf
            }
        }
        if (data == null) {
            Log.warning("ESP32: the device has no CDC data interface")
            return false
        }
        var inEp: UsbEndpoint? = null
        var outEp: UsbEndpoint? = null
        for (i in 0 until data.endpointCount) {
            val ep = data.getEndpoint(i)
            if (ep.type != UsbConstants.USB_ENDPOINT_XFER_BULK) {
                continue
            }
            if (ep.direction == UsbConstants.USB_DIR_IN) inEp = ep else outEp = ep
        }
        if (inEp == null || outEp == null) {
            Log.warning("ESP32: the CDC data interface has no bulk endpoints")
            return false
        }
        val conn = manager.openDevice(device)
        if (conn == null) {
            Log.warning("ESP32: could not open the USB device")
            return false
        }
        if (comm != null && !conn.claimInterface(comm, true)) {
            Log.warning("ESP32: could not claim the CDC control interface")
        }
        if (!conn.claimInterface(data, true)) {
            Log.warning("ESP32: could not claim the CDC data interface")
            conn.close()
            return false
        }
        val commIndex = comm?.id ?: 0
        // SET_LINE_CODING 921600 8N1, then SET_CONTROL_LINE_STATE with DTR on and RTS off.
        val coding = byteArrayOf(0x00, 0x10, 0x0E, 0x00, 0x00, 0x00, 0x08)
        conn.controlTransfer(0x21, 0x20, 0, commIndex, coding, coding.size, 500)
        conn.controlTransfer(0x21, 0x22, 0x01, commIndex, null, 0, 500)

        connection = conn
        controlInterface = comm
        dataInterface = data
        outEndpoint = outEp
        received.clear()
        pending = null
        pendingOffset = 0
        isOpen = true

        val readEndpoint: UsbEndpoint = inEp
        Thread({
            val buffer = ByteArray(512)
            while (isOpen && connection === conn) {
                val got = conn.bulkTransfer(readEndpoint, buffer, buffer.size, 100)
                if (got > 0) {
                    received.add(buffer.copyOf(got))
                } else if (got < 0 && findDevice(manager) == null) {
                    isOpen = false // Unplugged: read() reports the failure.
                }
            }
        }, "esp32-usb-reader").apply {
            isDaemon = true
            start()
        }
        Log.info("ESP32: USB link open")
        return true
    }

    @JvmStatic
    fun close() {
        synchronized(lock) { closeLocked() }
    }

    private fun closeLocked() {
        isOpen = false
        val conn = connection
        connection = null
        if (conn != null) {
            dataInterface?.let { conn.releaseInterface(it) }
            controlInterface?.let { conn.releaseInterface(it) }
            conn.close()
        }
        dataInterface = null
        controlInterface = null
        outEndpoint = null
    }

    /**
     * Waits up to [timeoutMs] for bytes. Returns the count, 0 on timeout, or -1 if the link is
     * down.
     */
    @JvmStatic
    fun read(buffer: ByteArray, timeoutMs: Int): Int {
        var filled = 0
        while (filled < buffer.size) {
            if (pending == null) {
                // Only the first wait may block; afterwards take whatever is already queued.
                pending = if (filled == 0) {
                    received.poll(timeoutMs.toLong(), TimeUnit.MILLISECONDS)
                } else {
                    received.poll()
                }
                pendingOffset = 0
                if (pending == null) {
                    break
                }
            }
            val chunk = pending!!
            val n = minOf(buffer.size - filled, chunk.size - pendingOffset)
            System.arraycopy(chunk, pendingOffset, buffer, filled, n)
            filled += n
            pendingOffset += n
            if (pendingOffset >= chunk.size) {
                pending = null
            }
        }
        if (filled == 0 && !isOpen) {
            return -1
        }
        return filled
    }

    @JvmStatic
    fun write(data: ByteArray, length: Int): Boolean {
        val conn = connection
        val out = outEndpoint
        if (!isOpen || conn == null || out == null) {
            return false
        }
        var sent = 0
        while (sent < length) {
            val got = conn.bulkTransfer(out, data, sent, length - sent, 2000)
            if (got <= 0) {
                return false
            }
            sent += got
        }
        return true
    }
}
