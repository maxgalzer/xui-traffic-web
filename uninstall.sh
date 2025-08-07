#!/bin/bash

INSTALL_DIR="/opt/xui-traffic-web"
SERVICE_NAME="xui-traffic-web"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

echo "=== Удаление XUI Traffic Web ==="

# Остановка сервиса
if systemctl is-active --quiet $SERVICE_NAME; then
    echo "Останавливаем сервис..."
    systemctl stop $SERVICE_NAME
fi

echo "Отключаем автозапуск..."
systemctl disable $SERVICE_NAME

# Удаление systemd unit
if [ -f "$SERVICE_FILE" ]; then
    rm -f "$SERVICE_FILE"
    systemctl daemon-reload
    echo "Systemd unit удалён."
fi

# Удаление файлов проекта
echo "Удаляем директорию $INSTALL_DIR..."
rm -rf "$INSTALL_DIR"

echo "XUI Traffic Web полностью удалён!"
