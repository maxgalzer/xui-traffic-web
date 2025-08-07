#!/bin/bash

set -e

INSTALL_DIR="/opt/xui-traffic-web"
PYTHON_BIN="python3"
PORT_DEFAULT=8060
ACCESS_LOG_DEFAULT="/usr/local/x-ui/access.log"
TIMEZONE_DEFAULT=0

echo -e "\n=== Установка XUI Traffic Web ===\n"

# 1. Обновление системы
echo "[1/8] Обновление системы..."
apt update -y && apt upgrade -y

# 2. Установка зависимостей
echo "[2/8] Установка python3, pip, git..."
apt install -y python3 python3-pip python3-venv git

# 3. Виртуальное окружение
echo "[3/8] Создание venv..."
cd $INSTALL_DIR
python3 -m venv venv
source venv/bin/activate

# 4. Установка python-библиотек
echo "[4/8] Установка зависимостей Python..."
pip install --upgrade pip
pip install -r requirements.txt

# 5. Настройка переменных
echo -e "\n--- Основные параметры ---"

read -p "Порт для интерфейса (по умолчанию $PORT_DEFAULT): " PORT
PORT=${PORT:-$PORT_DEFAULT}

read -p "Смещение времени (например, +5 для МСК) [${TIMEZONE_DEFAULT}]: " TZSHIFT
TZSHIFT=${TZSHIFT:-$TIMEZONE_DEFAULT}

read -p "Путь до access.log (по умолчанию $ACCESS_LOG_DEFAULT): " ACCESS_LOG_PATH
ACCESS_LOG_PATH=${ACCESS_LOG_PATH:-$ACCESS_LOG_DEFAULT}

read -p "Логин первого админа: " ADMIN_LOGIN
while [[ -z "$ADMIN_LOGIN" ]]; do
    echo "Логин не может быть пустым!"
    read -p "Логин первого админа: " ADMIN_LOGIN
done

read -s -p "Пароль первого админа: " ADMIN_PASS
echo
while [[ -z "$ADMIN_PASS" ]]; do
    echo "Пароль не может быть пустым!"
    read -s -p "Пароль первого админа: " ADMIN_PASS
    echo
done

SECRET_KEY=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 32)

echo -e "\n[5/8] Создание .env..."
cat > $INSTALL_DIR/.env <<EOF
PORT=$PORT
TIMEZONE_SHIFT=$TZSHIFT
ACCESS_LOG_PATH=$ACCESS_LOG_PATH
SECRET_KEY=$SECRET_KEY
EOF

# 6. Миграция БД + добавление админа
echo "[6/8] Инициализация базы и создание первого админа..."
source venv/bin/activate
export FLASK_APP=main.py
export ACCESS_LOG_PATH
export TIMEZONE_SHIFT=$TZSHIFT
export SECRET_KEY
$PYTHON_BIN <<END
import os
os.environ["ACCESS_LOG_PATH"] = "$ACCESS_LOG_PATH"
os.environ["TIMEZONE_SHIFT"] = str($TZSHIFT)
os.environ["SECRET_KEY"] = "$SECRET_KEY"
from main import init_db, init_admin
init_db()
init_admin("$ADMIN_LOGIN", "$ADMIN_PASS")
print(">>> Админ $ADMIN_LOGIN создан")
END

# 7. systemd unit
SERVICE_FILE="/etc/systemd/system/xui-traffic-web.service"
echo "[7/8] Настройка systemd unit..."
cat > $SERVICE_FILE <<EOF
[Unit]
Description=XUI Traffic Web Interface
After=network.target

[Service]
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/venv/bin/python3 main.py
Environment=PORT=$PORT
Environment=TIMEZONE_SHIFT=$TZSHIFT
Environment=ACCESS_LOG_PATH=$ACCESS_LOG_PATH
Environment=SECRET_KEY=$SECRET_KEY
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable xui-traffic-web
systemctl restart xui-traffic-web

# 8. Открытие порта (UFW)
if command -v ufw >/dev/null 2>&1; then
    ufw allow $PORT/tcp || true
    echo "[8/8] Порт $PORT открыт через ufw"
else
    echo "[8/8] UFW не найден, настройте доступ к порту $PORT вручную, если требуется."
fi

echo -e "\nУстановка завершена!"
echo "Интерфейс доступен по адресу: http://<ip_сервера>:$PORT"
echo "Логин: $ADMIN_LOGIN"
echo "Чтобы удалить сервис: bash uninstall.sh"
