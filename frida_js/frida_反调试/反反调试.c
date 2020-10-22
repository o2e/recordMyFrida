//反调试逻辑 :通过一直循环创建Socket连接，遍历端口，检查端口是否被占用，收到“REJECT”时，说明frida-server正在运行，直接杀掉进程。
//https://bbs.pediy.com/thread-260536.htm

v9 = a1;
v14 = &v6;
v13 = 16LL;
v12 = 0;
v11 = 16LL;
v10 = 16LL;
v15 = __memset_chk(&v6, 0LL, 16LL, 16LL);
v6 = 2;
inet_aton("0.0.0.0", &v8);
while ( 1 )
{
  for ( i = 1; i <= 65533; ++i )
  {
    v5 = socket(2LL, 1LL, 0LL);
    v7 = bswap32((unsigned __int16)i) >> 16;
    if ( (unsigned int)connect(v5, &v6, 16LL) != -1 )
    {
      v20 = &v2;
      v19 = 7LL;
      v18 = 0;
      v17 = 7LL;
      v16 = 7LL;
      v21 = __memset_chk(&v2, 0LL, 7LL, 7LL);
      v26 = v5;
      v25 = &unk_14A2;
      v24 = -1LL;
      v23 = 1LL;
      v22 = 0;
      v33 = v5;
      v32 = &unk_14A2;
      v31 = -1LL;
      v30 = 1LL;
      v29 = 0;
      v28 = 0LL;
      v27 = 0;
      sendto(v5, &unk_14A2, 1LL, 0LL, 0LL, 0LL);
      v38 = v5;
      v37 = "AUTH\r\n";
      v36 = -1LL;
      v35 = 6LL;
      v34 = 0;
      v45 = v5;
      v44 = "AUTH\r\n";
      v43 = -1LL;
      v42 = 6LL;
      v41 = 0;
      v40 = 0LL;
      v39 = 0;
      sendto(v5, "AUTH\r\n", 6LL, 0LL, 0LL, 0LL);
      usleep(500LL);
      v50 = v5;
      v49 = &v2;
      v48 = 7LL;
      v47 = 6LL;
      v46 = 64;
      v57 = v5;
      v56 = &v2;
      v55 = 7LL;
      v54 = 6LL;
      v53 = 64;
      v52 = 0LL;
      v51 = 0LL;
      v3 = recvfrom(v5, &v2, 6LL, 64LL, 0LL, 0LL);
      if ( v3 != -1 )
      {
        if ( (unsigned int)strcmp(&v2, "REJECT") )
        {
          __android_log_print(4LL, "pediy", "not FOUND FRIDA SERVER");
        }
        else
        {
          v1 = getpid();
          kill(v1, 9LL);
        }
      }
    }
    close(v5);
  }
}