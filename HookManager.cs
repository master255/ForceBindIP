using System;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using EasyHook;

namespace DHTMoney
{
    public static class HookManager
    {
        // ------------------- Native API -------------------
        [DllImport("ws2_32.dll", SetLastError = true)]
        static extern int bind(IntPtr s, ref sockaddr_in name, int namelen);

        [DllImport("ws2_32.dll", SetLastError = true)]
        static extern int bind(IntPtr s, ref sockaddr_in6 name, int namelen);

        [DllImport("ws2_32.dll", SetLastError = true)]
        static extern int setsockopt(IntPtr s, int level, int optname, ref int optval, int optlen);

        // ------------------- Delegates -------------------
        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        delegate int ConnectDelegate(IntPtr s, IntPtr name, int namelen);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        delegate int WSAConnectDelegate(IntPtr s, IntPtr name, int namelen,
            IntPtr lpCallerData, IntPtr lpCalleeData, IntPtr lpSQOS, IntPtr lpGQOS);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
        delegate int BindDelegate(IntPtr s, IntPtr name, int namelen);

        // ------------------- Hooks -------------------
        static LocalHook _connectHook, _wsaConnectHook;
        static LocalHook _bindHook;

        static ConnectDelegate _connectOriginal;
        static WSAConnectDelegate _wsaConnectOriginal;
        static BindDelegate _bindOriginal;

        // ------------------- Structs -------------------
        [StructLayout(LayoutKind.Sequential)]
        struct sockaddr_in
        {
            public short sin_family;
            public ushort sin_port;
            public uint sin_addr;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public byte[] sin_zero;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct sockaddr_in6
        {
            public short sin6_family;
            public ushort sin6_port;
            public uint sin6_flowinfo;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] sin6_addr;
            public uint sin6_scope_id;
        }

        // ------------------- Adapter IPs -------------------
        static IPAddress _localIPv4;
        static IPAddress _localIPv6;
        static int _ifIndexIPv4;
        static int _ifIndexIPv6;

        // ------------------- Constants -------------------
        const int IPPROTO_IP = 0;
        const int IPPROTO_IPV6 = 41;
        const int IP_UNICAST_IF = 31;
        const int IPV6_UNICAST_IF = 31;

        public static void InstallHooks()
        {
            GetPhysicalAdapterIPs(out _localIPv4, out _localIPv6, out _ifIndexIPv4, out _ifIndexIPv6);
            //Console.WriteLine($"IPv4: {_localIPv4} (ifIndex {_ifIndexIPv4})");
            //Console.WriteLine($"IPv6: {_localIPv6} (ifIndex {_ifIndexIPv6})");
            // connect
            IntPtr connectPtr = LocalHook.GetProcAddress("ws2_32.dll", "connect");
            _connectHook = LocalHook.Create(connectPtr, new ConnectDelegate(Connect_Hook), null);
            _connectOriginal = (ConnectDelegate)Marshal.GetDelegateForFunctionPointer(connectPtr, typeof(ConnectDelegate));
            _connectHook.ThreadACL.SetExclusiveACL(new int[0]);
            // WSAConnect
            IntPtr wsaConnectPtr = LocalHook.GetProcAddress("ws2_32.dll", "WSAConnect");
            _wsaConnectHook = LocalHook.Create(wsaConnectPtr, new WSAConnectDelegate(WSAConnect_Hook), null);
            _wsaConnectOriginal = (WSAConnectDelegate)Marshal.GetDelegateForFunctionPointer(wsaConnectPtr, typeof(WSAConnectDelegate));
            _wsaConnectHook.ThreadACL.SetExclusiveACL(new int[0]);
            // bind
            IntPtr bindPtr = LocalHook.GetProcAddress("ws2_32.dll", "bind");
            _bindHook = LocalHook.Create(bindPtr, new BindDelegate(Bind_Hook), null);
            _bindOriginal = (BindDelegate)Marshal.GetDelegateForFunctionPointer(bindPtr, typeof(BindDelegate));
            _bindHook.ThreadACL.SetExclusiveACL(new int[0]);
        }

        // ------------------- TCP Hooks -------------------
        static int Connect_Hook(IntPtr s, IntPtr name, int namelen)
        {
            ForceBindTcp(s, name);
            return _connectOriginal(s, name, namelen);
        }

        static int WSAConnect_Hook(IntPtr s, IntPtr name, int namelen,
            IntPtr lpCallerData, IntPtr lpCalleeData, IntPtr lpSQOS, IntPtr lpGQOS)
        {
            ForceBindTcp(s, name);
            return _wsaConnectOriginal(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS);
        }

        static void ForceBindTcp(IntPtr sock, IntPtr name)
        {
            short family = Marshal.ReadInt16(name);
            if (family == 2 && _localIPv4 != null)
            {
                setsockopt(sock, IPPROTO_IP, IP_UNICAST_IF, ref _ifIndexIPv4, sizeof(int));
                ushort port = (ushort)((Marshal.ReadByte(name, 2) << 8) | Marshal.ReadByte(name, 3));
                sockaddr_in local = new sockaddr_in
                {
                    sin_family = 2,
                    sin_port = port,
                    sin_addr = BitConverter.ToUInt32(_localIPv4.GetAddressBytes(), 0),
                    sin_zero = new byte[8]
                };
                bind(sock, ref local, Marshal.SizeOf(typeof(sockaddr_in)));
            }
            else if (family == 23 && _localIPv6 != null)
            {
                setsockopt(sock, IPPROTO_IPV6, IPV6_UNICAST_IF, ref _ifIndexIPv6, sizeof(int));
                ushort port = (ushort)((Marshal.ReadByte(name, 2) << 8) | Marshal.ReadByte(name, 3));
                uint flowinfo = (uint)(
                    (Marshal.ReadByte(name, 4) << 24) |
                    (Marshal.ReadByte(name, 5) << 16) |
                    (Marshal.ReadByte(name, 6) << 8) |
                    Marshal.ReadByte(name, 7)
                );
                sockaddr_in6 local6 = new sockaddr_in6
                {
                    sin6_family = 23,
                    sin6_port = port,
                    sin6_flowinfo = flowinfo,
                    sin6_addr = _localIPv6.GetAddressBytes(),
                    sin6_scope_id = (uint)_ifIndexIPv6
                };
                bind(sock, ref local6, Marshal.SizeOf(typeof(sockaddr_in6)));
            }
        }

        static int Bind_Hook(IntPtr s, IntPtr name, int namelen)
        {
            try
            {
                short family = Marshal.ReadInt16(name);
                if (family == 2 && _localIPv4 != null)
                {
                    byte[] ipBytes = _localIPv4.GetAddressBytes();
                    Marshal.Copy(ipBytes, 0, IntPtr.Add(name, 4), 4);
                    return _bindOriginal(s, name, namelen);
                }
                else if (family == 23 && _localIPv6 != null) // IPv6
                {
                    byte[] ipBytes = _localIPv6.GetAddressBytes();
                    Marshal.Copy(ipBytes, 0, IntPtr.Add(name, 8), 16);
                    Marshal.WriteInt32(name, 24, _ifIndexIPv6);
                    return _bindOriginal(s, name, namelen);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[Bind_Hook error] " + ex);
            }
            return _bindOriginal(s, name, namelen);
        }

        static void GetPhysicalAdapterIPs(out IPAddress ipv4, out IPAddress ipv6, out int ifIdx4, out int ifIdx6)
        {
            ipv4 = null; ipv6 = null; ifIdx4 = 0; ifIdx6 = 0;

            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up) continue;
                if (nic.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                if ((nic.Description?.ToLower() ?? "").Contains("dhtmoneyvpn") || nic.Description.Contains("WSL") || nic.Description.Contains("VMware")|| nic.Description.Contains("Hyper-V")) continue;

                var props = nic.GetIPProperties();
                foreach (var ua in props.UnicastAddresses)
                {
                    if (ua.Address.AddressFamily == AddressFamily.InterNetwork && ipv4 == null)
                    {
                        ipv4 = ua.Address;
                        ifIdx4 = props.GetIPv4Properties()?.Index ?? 0;
                    }
                    if (ua.Address.AddressFamily == AddressFamily.InterNetworkV6 && ipv6 == null && !ua.Address.IsIPv6LinkLocal)
                    {
                        ipv6 = ua.Address;
                        ifIdx6 = props.GetIPv6Properties()?.Index ?? 0;
                    }
                }
                if (ipv4 != null && ipv6 != null) break;
            }
        }
    }
}
