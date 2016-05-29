# CSharp TrainerAPI

Usage
========

     MemoryAPIv1 MAV1 = new MemoryAPIv1(GameWindowsTitle, GameExecutable, GameModuleName);

     IntPtr GameBaseAddress = MAV1.GetBaseModule(GameModuleName);

     //Offset Run 1
     MAV1.WriteFloatPointer((IntPtr)((int)GameBaseAddress + 0x00E68E40), new int[] { 0x14, 0xec, 0x10, 0x1c, 0x2c }, float.Parse(msText.Text));


Memory API
===============

* GetBaseModule
* GetAddressPointer
* WriteByteArray
* WriteInt
* WriteDouble
* WriteFloat
* WriteStringA
* WriteStringW
* ReadInt
* ReadDouble
* ReadFloat
* ReadBytes

Memory API.V1
================

* MemoryAPI + Pointer Capable
* AOB Capable

ProcessAPI
================

* Create/Resume/Suspend Process

