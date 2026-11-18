@echo off
rem Two Azahar instances on the virtual air (ESP32 radio path, no hardware). Options pass through,
rem e.g.  virtual-air-pair.cmd -Loss 0.1 -JitterMs 5    or    virtual-air-pair.cmd -Setup
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0virtual-air-pair.ps1" %*
