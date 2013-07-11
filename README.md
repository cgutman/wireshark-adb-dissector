wireshark-adb
=============

Android Debug Bridge (ADB) Protocol Parser for Wireshark

To run: Execute wireshark with "-X lua_script:<path to script>" option.

Usage notes:

1) By default, the dissector will automatically parse packets on TCP port 5555 (the default port for ADB devices).

2) The dissector will add the "adb" protocol (which can be used to filter for just ADB packets).

3) You can also filter based on the type of ADB packet (adb.cnxn, adb.okay, adb.open, adb.close, adb.write, adb.auth, etc)

4) The protocol parser will mark fields that appear corrupt or violate ADB 1.0 protocol spec.
