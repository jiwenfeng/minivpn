/*
 * MiniVPN - Linux TUN 设备管理
 *
 * 使用 /dev/net/tun + ioctl 实现 TUN 设备的创建与配置
 */

#ifndef MINIVPN_TUN_H
#define MINIVPN_TUN_H

/*
 * 创建 TUN 设备
 *
 * @param dev_name       输出: 设备名 (如 "tun0")，调用者需预分配缓冲区
 * @param dev_name_size  dev_name 缓冲区大小
 * @return               TUN 设备文件描述符, 失败返回-1
 */
int tun_create(char *dev_name, int dev_name_size);

/*
 * 配置 TUN 设备 IP 地址
 *
 * @param dev_name   设备名 (如 "tun0")
 * @param local_ip   本端 IP 地址 (如 "172.16.0.1")
 * @param peer_ip    对端 IP 地址 (如 "172.16.0.2")
 * @return           0成功, -1失败
 */
int tun_configure(const char *dev_name, const char *local_ip, const char *peer_ip);

/*
 * 设置 TUN 设备 MTU
 *
 * @param dev_name  设备名
 * @param mtu       MTU 值
 * @return          0成功, -1失败
 */
int tun_set_mtu(const char *dev_name, int mtu);

#endif /* MINIVPN_TUN_H */
