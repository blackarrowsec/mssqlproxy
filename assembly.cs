/*
* Copyright (c) 2020 BlackArrow
*
* Author:
*  Pablo Martinez (https://twitter.com/xassiz)
*
*/

using System;
using System.Data;
using System.Data.SqlClient;
using System.Data.SqlTypes;
using Microsoft.SqlServer.Server;
using System.IO;
using System.Diagnostics;
using System.Text;

using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Net.NetworkInformation;
using System.Net;
using System.Collections;



static class NativeMethods
{
    [DllImport("kernel32.dll")]
    public static extern IntPtr LoadLibrary(string dllToLoad);

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procedureName);

    [DllImport("kernel32.dll")]
    public static extern bool FreeLibrary(IntPtr hModule);
}



public partial class StoredProcedures
{
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate int main(string client_addr, int client_port);
    
    
    [Microsoft.SqlServer.Server.SqlProcedure]
    public static void sp_start_proxy (string path, string client_addr, int client_port)
    {
        string msg = "ok";
        
        IntPtr pDll = NativeMethods.LoadLibrary(path);
        if(pDll == IntPtr.Zero){
            msg = "error LoadLibrary";
        }
        else {
            IntPtr func = NativeMethods.GetProcAddress(pDll, "main");
            if(func == IntPtr.Zero){
                msg = "error GetProcAddress";
            }
            else {
                main m = (main)Marshal.GetDelegateForFunctionPointer(func, typeof(main));
                
                m(client_addr, client_port);                                                                                        
            }
            NativeMethods.FreeLibrary(pDll);
        }
        
    
        // Create the record and specify the metadata for the columns.
        SqlDataRecord record = new SqlDataRecord(new SqlMetaData("output", SqlDbType.NVarChar, 4000));
        
        // Mark the beginning of the result set.
        SqlContext.Pipe.SendResultsStart(record);

        // Set values for each column in the row
        record.SetString(0, msg);

        // Send the row back to the client.
        SqlContext.Pipe.SendResultsRow(record);
        
        // Mark the end of the result set.
        SqlContext.Pipe.SendResultsEnd();
        
    }
};





