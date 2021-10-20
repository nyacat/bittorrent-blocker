# bittorrent-block

- 限制吸血客户端，例如迅雷，先锋影音等
- 支持ipv4 ipv6

<br />

- Restrictions on well-known download only clients
- Support IPv4&IPv6

## 截图 Screenshots
![Snipaste_2021-10-10_07-26-32](https://user-images.githubusercontent.com/2476717/136676182-88a6584e-8fbd-4a97-b6a1-edebac27dc90.png)
![Snipaste_2021-10-10_07-25-32](https://user-images.githubusercontent.com/2476717/136676184-5dfd7405-6e1a-43d2-ad7f-d836da74f29c.png)


## 使用说明 Instruction

### 依赖

`pip3 install requests`

安装 ipset

`apt install ipset`

### 启动

使用root权限，或者其他能使用iptables/ipset命令的用户运行脚本

`python3 block_peer.py`

## 测试环境
Debian 11

## 其他说明
如需守护运行，请使用systemd或者screen挂后台

rtorrent 版本仅测试过unix domain socket的scgi，如果是tcp的请自行修改代码
