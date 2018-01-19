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
using System.Threading;
using System.IO;
using System.Collections.ObjectModel;
using System.Collections.Specialized;

namespace FindSubnetIP
{
	class Program
	{
		/// <summary>
		/// 
		/// </summary>
		public class IPinfomation
		{
			public string MAC;
			public string IP;
			/// <summary>
			/// 上次更新时间
			/// </summary>
			public DateTime UpdateTime;
		}

		static void Main(string[] args)
		{
			var iplist = new ObservableCollection<IPinfomation>();

			iplist.CollectionChanged += (X, Y) =>
			{
				Console.Clear();
				foreach (var item in iplist)
				{
					Console.WriteLine($"{item.IP} {item.MAC}");
				}

				//MessageBox.Show(X.ToString());
				//if (Y.Action == NotifyCollectionChangedAction.Add) MessageBox.Show(Y.NewItems[0].ToString());
				//if (Y.Action == NotifyCollectionChangedAction.Remove) MessageBox.Show(Y.OldItems[0].ToString());
			};

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
				using (var filter = communicator.CreateFilter("arp")) communicator.SetFilter(filter);
				var s_ipv4 = ipv4s[0].Address.ToString();
				var s_brc = ipv4s[0].Broadcast.ToString();
				var s_mask = ipv4s[0].Netmask.ToString();
				s_ipv4 = s_ipv4.Substring(s_ipv4.IndexOf(' ') + 1);
				s_brc = s_brc.Substring(s_brc.IndexOf(' ') + 1);
				s_mask = s_mask.Substring(s_mask.IndexOf(' ') + 1);

				var bs_ipv4 = s_ipv4.IPv4ToBytes();

				//广播地址,这个参数通常无用
				var bs_brc = s_brc.IPv4ToBytes();

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
						Parallel.For(1, segment_max, i =>
						{
							var ip_index = BitConverter.GetBytes(segment + i.Reverse()).BytesToIPv4();
							var dnsresult = MakePacker.BuildArpPacket(selectedDevice.GetMacAddress().ToString(), s_ipv4, "00:00:00:00:00:00", ip_index);
							communicator.SendPacket(dnsresult);
							//Console.WriteLine($"{DateTime.Now.Ticks} {ip_index}");
						});
						Thread.Sleep(30000);
					}
				});
				// start the capture
				communicator.ReceivePackets(0, (packet) =>
				{
					var buff = new MemoryStream(packet.Buffer);
					if (buff.Length != 0x2A) return;
					//数据链路层-目标MAC
					var data_destination_mac = new byte[6];
					//数据链路层-源MAC
					var data_source_mac = new byte[6];
					//协议
					var protocol = new byte[2];
					//操作
					var operation = new byte[2];
					//源MAC地址
					var source_mac = new byte[6];
					//源IP地址
					var source_ip = new byte[4];
					//目标MAC地址
					var destination_mac = new byte[6];
					//目标IP地址
					var destination_ip = new byte[4];

					buff.Read(data_destination_mac, 0, 6);
					buff.Read(data_source_mac, 0, 6);
					buff.Read(protocol, 0, 2);

					if (protocol[0] != 8 || protocol[1] != 6)
					{
						//并不是arp协议
						return;
					}

					//跳过类型 IP MAC长度 IP长度
					buff.Seek(6, SeekOrigin.Current);

					buff.Read(operation, 0, 2);
					if (operation[0] != 0 || operation[1] != 2)
					{//不是应答包
						return;
					}

					buff.Read(source_mac, 0, 6);
					buff.Read(source_ip, 0, 4);
					buff.Read(destination_mac, 0, 6);
					buff.Read(destination_ip, 0, 4);

					var s_mac = source_mac.BytesToMAC();
					var s_ip = source_ip.BytesToIPv4();
					var has = false;
					var dt = DateTime.Now;
					foreach (var item in iplist)
					{
						if (item.IP != s_ip) continue;
						item.MAC = s_mac;
						has = true;
						item.UpdateTime = dt;
					}
					if (!has) iplist.Add(new IPinfomation() { UpdateTime = dt, IP = s_ip, MAC = s_mac });

					for (var i = iplist.Count - 1; i < 0; i--)
					{
						var ticks = (dt - iplist[i].UpdateTime).Ticks;
						if (ticks > 100 * 1000) iplist.Remove(iplist[i]);
					}

					//buff.Read();
					//Console.WriteLine(packet.Timestamp.ToString("yyyy-MM-dd hh:mm:ss.fff") + " length:" + packet.Length);
					//packet.Ethernet.Source.ToValue();
					//var ip = packet.Ethernet.IpV4;
					//Console.WriteLine($"{ ip.Source } -> { ip.Destination }");
					//var protocol = ip.Protocol;

					//communicator.Break();
					//Console.Write(BitConverter.ToString(packet.Buffer));
				});
				//communicator.SendPacket()
			}

		}
	}
}
