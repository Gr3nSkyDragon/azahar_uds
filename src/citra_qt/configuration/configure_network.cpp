// Copyright 2026 Citra Emulator Project / Azahar Emulator Project
// Licensed under GPLv2 or any later version
// Refer to the license.txt file included.

#include <QFutureWatcher>
#include <QIcon>
#include <QMessageBox>
#include <QtConcurrent/QtConcurrentRun>
#include "citra_qt/configuration/configure_network.h"
#include "citra_qt/uisettings.h"
#include "core/hle/service/nwm/uds_real/esp32_probe.h"
#include "ui_configure_network.h"

ConfigureWeb::ConfigureWeb(QWidget* parent)
    : QWidget(parent), ui(std::make_unique<Ui::ConfigureWeb>()) {
    ui->setupUi(this);

#ifndef ENABLE_DISCORD_RPC
    ui->discord_group->setEnabled(false);
#endif
#ifndef ENABLE_WEB_SERVICE
    ui->web_api_url_lineedit->setEnabled(false);
    ui->token_lineedit->setEnabled(false);
#endif
#ifndef _WIN32
    // The ESP32 backend is wired up for Windows (here) and Android (its own settings screen).
    ui->esp32_group->setVisible(false);
#endif
    connect(ui->esp32_connect_button, &QPushButton::clicked, this, &ConfigureWeb::ConnectEsp32);
    SetConfiguration();
}

ConfigureWeb::~ConfigureWeb() = default;

void ConfigureWeb::ShowEsp32Status(const Service::NWM::UdsReal::Esp32::DeviceStatus& status) {
    ui->esp32_status_label->setText(QString::fromStdString(status.message));
}

// Looks for the board without opening it, so the dialog shows whether it is plugged in.
void ConfigureWeb::RefreshEsp32Status() {
    ShowEsp32Status(Service::NWM::UdsReal::Esp32::FindDevice());
}

// Opens the board and checks it answers, off the UI thread (the handshake can take seconds).
void ConfigureWeb::ConnectEsp32() {
    if (esp32_probe_running) {
        return;
    }
    esp32_probe_running = true;
    ui->esp32_connect_button->setEnabled(false);
    ui->esp32_status_label->setText(tr("Connecting..."));

    auto* watcher = new QFutureWatcher<Service::NWM::UdsReal::Esp32::DeviceStatus>(this);
    connect(watcher, &QFutureWatcherBase::finished, this, [this, watcher] {
        ShowEsp32Status(watcher->result());
        ui->esp32_connect_button->setEnabled(true);
        esp32_probe_running = false;
        watcher->deleteLater();
    });
    watcher->setFuture(QtConcurrent::run([] { return Service::NWM::UdsReal::Esp32::Probe(); }));
}

void ConfigureWeb::SetConfiguration() {

    ui->web_api_url_lineedit->setText(
        QString::fromStdString(Settings::values.web_api_url.GetValue()));
    ui->token_lineedit->setText(QString::fromStdString(Settings::values.network_token.GetValue()));
    ui->toggle_esp32->setChecked(Settings::values.use_esp32_uds.GetValue());
    RefreshEsp32Status();

#ifdef ENABLE_DISCORD_RPC
    ui->toggle_discordrpc->setChecked(UISettings::values.enable_discord_presence.GetValue());
#endif
}

void ConfigureWeb::ApplyConfiguration() {
#ifdef ENABLE_DISCORD_RPC
    UISettings::values.enable_discord_presence = ui->toggle_discordrpc->isChecked();
#endif

    Settings::values.web_api_url = ui->web_api_url_lineedit->text().toStdString();
    Settings::values.network_token = ui->token_lineedit->text().toStdString();
    Settings::values.use_esp32_uds = ui->toggle_esp32->isChecked();
}

void ConfigureWeb::RetranslateUI() {
    ui->retranslateUi(this);
}
