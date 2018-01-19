using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace nettools
{
	public static class extent
	{
		/// <summary>
		/// 
		/// </summary>
		public enum Endian : byte
		{
			/// <summary>
			/// 大端序
			/// </summary>
			BigEndian = 0,
			/// <summary>
			/// 小端序
			/// </summary>
			LittleEndian = 1,
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="mac"></param>
		/// <returns></returns>
		public static byte[] MACToBytes(this string mac)
		{
			var temp = new List<byte>();
			var num = "";
			foreach (var c in mac.ToUpper())
			{
				if ((c < '0' || c > '9') && (c < 'A' || c > 'F'))
				{
					temp.Add(byte.Parse(num, System.Globalization.NumberStyles.AllowHexSpecifier));
					num = "";
					continue;
				}
				num += c;
			}
			if (!string.IsNullOrWhiteSpace(num)) temp.Add(byte.Parse(num, System.Globalization.NumberStyles.AllowHexSpecifier));
			if (temp.Count != 6) throw new Exception("请输入正确的MAC地址!");
			return temp.ToArray();
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="ipv4"></param>
		/// <returns></returns>
		public static byte[] IPv4ToBytes(this string ipv4)
		{
			var temp = new List<byte>();
			var num = "";
			foreach (var c in ipv4.ToUpper())
			{
				if ((c < '0' || c > '9') && (c < 'A' || c > 'F'))
				{
					temp.Add(byte.Parse(num, System.Globalization.NumberStyles.AllowDecimalPoint));
					num = "";
					continue;
				}
				num += c;
			}
			if (!string.IsNullOrWhiteSpace(num)) temp.Add(byte.Parse(num, System.Globalization.NumberStyles.AllowDecimalPoint));
			if (temp.Count != 4) throw new Exception("请输入正确的IPv4地址!");
			return temp.ToArray();
		}


		/// <summary>
		/// 
		/// </summary>
		/// <param name="bs"></param>
		/// <returns></returns>
		public static string BytesToMAC(this byte[] bs)
		{
			if (bs.Length != 6) throw new Exception("请传入6个byte!");
			return $"{bs[0].ToString("x2")}:{bs[1].ToString("x2")}:{bs[2].ToString("x2")}:{bs[3].ToString("x2")}:{bs[4].ToString("x2")}:{bs[5].ToString("x2")}".ToUpper();
		}


		/// <summary>
		/// 
		/// </summary>
		/// <param name="bs"></param>
		/// <returns></returns>
		public static string BytesToIPv4(this byte[] bs)
		{
			if (bs.Length != 4) throw new Exception("请传入4个byte!");
			return $"{bs[0].ToString()}.{bs[1].ToString()}.{bs[2].ToString()}.{bs[3].ToString()}";
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="num"></param>
		/// <returns></returns>
		public static int Reverse(this int num)
		{
			return BitConverter.ToInt32(BitConverter.GetBytes(num).Reverse().ToArray(), 0);
		}


		/// <summary>
		/// 
		/// </summary>
		/// <param name="ms"></param>
		/// <param name="endian"></param>
		/// <returns></returns>
		public static UInt16 ReadUInt16(this MemoryStream ms, Endian endian = Endian.LittleEndian)
		{
			var temp = ms.ReadByte();
			if (endian == Endian.BigEndian) return (UInt16)((temp * 0x100) + ms.ReadByte());
			if (endian == Endian.LittleEndian) return (UInt16)((ms.ReadByte() * 0x100) + temp);
			throw new InvalidDataException("传入了无效的端序!");
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="ms"></param>
		/// <param name="endian"></param>
		/// <returns></returns>
		public static Int16 ReadInt16(this MemoryStream ms, Endian endian = Endian.LittleEndian)
		{
			var temp = ms.ReadByte();
			if (endian == Endian.BigEndian) return (Int16)((temp * 0x100) + ms.ReadByte());
			if (endian == Endian.LittleEndian) return (Int16)((ms.ReadByte() * 0x100) + temp);
			throw new InvalidDataException("传入了无效的端序!");
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="ms"></param>
		/// <param name="endian"></param>
		/// <returns></returns>
		public static UInt32 ReadUInt32(this MemoryStream ms, Endian endian = Endian.LittleEndian)
		{
			var temp = new byte[4];
			ms.Read(temp, 0, 4);
			if (endian == Endian.BigEndian) return (UInt32)((temp[0] * 0x1000000) + (temp[1] * 0x10000) + (temp[2] * 0x100) + temp[3]);
			if (endian == Endian.LittleEndian) return (UInt32)((temp[3] * 0x1000000) + (temp[2] * 0x10000) + (temp[1] * 0x100) + temp[0]);
			throw new InvalidDataException("传入了无效的端序!");
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="ms"></param>
		/// <param name="endian"></param>
		/// <returns></returns>
		public static Int32 ReadInt32(this MemoryStream ms, Endian endian = Endian.LittleEndian)
		{
			var temp = new byte[4];
			ms.Read(temp, 0, 4);
			if (endian == Endian.BigEndian) return (temp[0] * 0x1000000) + (temp[1] * 0x10000) + (temp[2] * 0x100) + temp[3];
			if (endian == Endian.LittleEndian) return (temp[3] * 0x1000000) + (temp[2] * 0x10000) + (temp[1] * 0x100) + temp[0];
			throw new InvalidDataException("传入了无效的端序!");
		}


	}//class
}
