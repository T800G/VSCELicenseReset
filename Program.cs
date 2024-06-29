//alternate registry view functions require .Net Framework 4
//compile from command line with:
//C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /target:winexe Program.cs


using System;
using System.Security.Principal;
using Microsoft.Win32;
using System.Security.Cryptography;


namespace VSCELicenseReset
{
	class Program
	{
		
		
		static byte[] ConvertToBinaryDate(byte[] DecryptedData, int Year, int Month, int Day)
        {
            // Year
            byte[] YearB = BitConverter.GetBytes(Year);
            DecryptedData[DecryptedData.Length - 16] = YearB[0];
            DecryptedData[DecryptedData.Length - 15] = YearB[1];

            // Month
            byte[] MonthB = BitConverter.GetBytes(Month);
            DecryptedData[DecryptedData.Length - 14] = MonthB[0];
            DecryptedData[DecryptedData.Length - 13] = MonthB[1];

            // Day
            byte[] DayB = BitConverter.GetBytes(Day);
            DecryptedData[DecryptedData.Length - 12] = DayB[0];
            DecryptedData[DecryptedData.Length - 11] = DayB[1];

            return DecryptedData;
        }
		
		
        static string ConvertFromBinaryDate(byte[] DecryptedData)
        {
            // Year
            byte[] YearB = new byte[2];
            YearB[0] = DecryptedData[DecryptedData.Length - 15];
            YearB[1] = DecryptedData[DecryptedData.Length - 16];

            string YearS = "";
            YearS += BitConverter.ToString(YearB, 0, 1);
            YearS += BitConverter.ToString(YearB, 1, 1);

            int YearI = int.Parse(YearS, System.Globalization.NumberStyles.HexNumber);

            // Month
            byte[] MonthB = new byte[2];
            MonthB[0] = DecryptedData[DecryptedData.Length - 13];
            MonthB[1] = DecryptedData[DecryptedData.Length - 14];

            string MonthS = "";
            MonthS += BitConverter.ToString(MonthB, 0, 1);
            MonthS += BitConverter.ToString(MonthB, 1, 1);

            int MonthI = int.Parse(MonthS, System.Globalization.NumberStyles.HexNumber);

            // Day
            byte[] DayB = new byte[2];
            DayB[0] = DecryptedData[DecryptedData.Length - 11];
            DayB[1] = DecryptedData[DecryptedData.Length - 12];

            string DayS = "";
            DayS += BitConverter.ToString(DayB, 0, 1);
            DayS += BitConverter.ToString(DayB, 1, 1);

            int DayI = int.Parse(DayS, System.Globalization.NumberStyles.HexNumber);
            
            string ExpirationDate = String.Format("{0:00}", DayI) + "/" + String.Format("{0:00}", MonthI) + "/" + YearI.ToString();

            return ExpirationDate;
        }	
		

		
		public static void Main(string[] args)
		{
			if (! new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator))
			{
				Console.WriteLine("This program must be run as Administrator");
				Console.ReadKey(true);
				return;
			}
			
			string[] sRegkeys = {
							@"Licenses\E79B3F9C-6543-4897-BBA5-5BFB0A02BB5C\06177", //VS 2013 Community Edition
							@"Licenses\4D8CFBCB-2F6A-4AD2-BABF-10E28F6F2C8F\07078", //VS 2015 Community Edition
							@"Licenses\5C505A59-E312-4B89-9508-E162F8150517\08878", //VS 2017 Community Edition
							@"Licenses\41717607-F34E-432C-A138-A3CFD7E25CDA\09278", //VS 2019 Community Edition
							};
			
			foreach (string sRegKey in sRegkeys)
			{				
				try {
					
				RegistryKey rkbase = RegistryKey.OpenBaseKey(Microsoft.Win32.RegistryHive.ClassesRoot, RegistryView.Registry64);				
				RegistryKey rkey = rkbase.OpenSubKey(sRegKey, true);

				byte[] binData = (byte[])rkey.GetValue(String.Empty);
				Console.WriteLine (sRegKey);
				Console.WriteLine("got binary data");
				
				byte[] origData = ProtectedData.Unprotect( binData, null, DataProtectionScope.LocalMachine);
				Console.WriteLine("got original data");
				
				Console.WriteLine("expiration date=" + ConvertFromBinaryDate(origData) );

				DateTime expDate = DateTime.Today.AddDays(30); //31 days max
				Console.WriteLine("new expiration date=" + expDate.ToString());
				
				byte[] newData = ConvertToBinaryDate(origData, expDate.Year, expDate.Month, expDate.Day);
				byte[] encrData = ProtectedData.Protect(newData, null, DataProtectionScope.LocalMachine);
				rkey.SetValue(String.Empty, encrData);
				rkey.Close();				
				rkbase.Close();
				
				Console.WriteLine("saved new data");
				
				
				} catch (Exception ex)
				{
					Console.WriteLine("key '" + sRegKey + "' not found");
					Console.WriteLine("Error: " + ex.Message);
				}
			}

			Console.WriteLine("Press any key to continue . . . ");
			Console.ReadKey(true);
		}
	}
}