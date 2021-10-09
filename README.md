# transmission-block

限制吸血客户端，例如迅雷，先锋影音等

## 使用说明

安装依赖

`pip3 install requests`

安装 ipset

`apt install ipset`

使用root权限，或者其他能使用iptables/ipset命令的用户启动脚本

`python3 block_peer.py`

## 测试环境
Debian 11

## 其他说明
如需守护运行，请使用systemd或者screen挂后台
