using System.Runtime.InteropServices;

namespace ModularCA.Keystore.Secure;

public static class SecureMemoryUtils
{
	public static void ZeroMemory(byte[] data)
	{
		if (data == null) return;
		for (int i = 0; i < data.Length; i++)
			data[i] = 0;
	}

	public static void DisposeSecure(ref byte[]? data)
	{
		if (data == null) return;
		ZeroMemory(data);
		data = null;
	}
}
