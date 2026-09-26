// Copyright 2026 Citra Emulator Project / Azahar Emulator Project
// Licensed under GPLv2 or any later version
// Refer to the license.txt file included.

#pragma once

#include <memory>
#include <QWidget>

namespace Service::NWM::UdsReal::Esp32 {
struct DeviceStatus;
}

namespace Ui {
class ConfigureWeb;
}

class ConfigureWeb : public QWidget {
    Q_OBJECT

public:
    explicit ConfigureWeb(QWidget* parent = nullptr);
    ~ConfigureWeb() override;

    void ApplyConfiguration();
    void RetranslateUI();
    void SetConfiguration();

private:
    void RefreshEsp32Status();
    void ConnectEsp32();
    void ShowEsp32Status(const Service::NWM::UdsReal::Esp32::DeviceStatus& status);

    std::unique_ptr<Ui::ConfigureWeb> ui;
    bool esp32_probe_running = false;
};
