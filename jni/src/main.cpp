//微验网络验证//
//如果是AIDE编译jni，请将原main.cpp删除，将此注入好的文件改成main.cpp
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <dirent.h>
#include <pthread.h>
#include <fstream>
#include <string.h>
#include <time.h>
#include <malloc.h>
#include <iostream>
#include <fstream>
#include "res/weiyan.h"
#include "res/cJSON.h"
#include "res/Encrypt.h"
#include<iostream>
#include<ctime>
using namespace std;
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <dirent.h>
#include <pthread.h>
#include <fstream>
#include <string.h>
#include "draw.h"
#include <sys/stat.h>
#include <time.h>
#include <malloc.h>
#include <iostream>
#include <fstream>
#include<iostream>
#include<ctime>
using namespace std;

static bool 触摸驱动;

bool isDirectoryExist(const std::string& path) {
    struct stat info;
    if (stat(path.c_str(), &info) != 0) {
        return false;
    } else if (info.st_mode & S_IFDIR) {
        return true;
    } else {
        return false;
    }
}


int main(){
    const static char *_wyHost = "wy.llua.cn";
	const static char *_wyAppid = "12274";	
	const static char *_wyAppkey = "YaWZ175nEz39m571";
	const static char *_wyRc4key = "0ef0850c2b1b9fdd872a37163906b4e5";
	// 以上信息勿动
	
	const static char *_kmPath = "/sdcard/km";
	// 卡密路径

	const static char *_imeiPath = "/sdcard/imei";
	// 机器码路径
	
	const static bool _ggSwitch = false;
	// 公告开关

	printf("\033[35;1m");		// 粉红色
	printf("欢迎使用XF内核 XF内核为您保驾护航[%s]\n",_wyAppid);
	printf("\033[32;1m");		// 绿色
	printf("\n已支持新赛季s39 支持15系统 作者:小凡大帅哥\n\n");
	printf("\033[33;1m");		// 黄色

	if (_ggSwitch){
	    char _ggUrl[1024];
	    sprintf(_ggUrl, "app=%s",_wyAppid);
    	char *_ggData = httppost(_wyHost,"api/?id=notice",_ggUrl);
    	char* _deggData=Decrypt(_ggData, _wyRc4key);
    	cJSON *_ggJson = cJSON_Parse(_deggData);
    	int _ggCode = cJSON_GetObjectItem(_ggJson, "code")->valueint;
    	if (_ggCode == 200){
    		cJSON *_ggMsg = cJSON_GetObjectItem(_ggJson, "msg");
            char *_appgg = cJSON_GetObjectItem(_ggMsg, "app_gg")->valuestring;
    	    printf("\n\n公告:%s\n\n",_appgg);
    	}
	}
	
	home_main:
	char _Kami[40];
	if (fopen(_kmPath, "r") == NULL)
	{
		printf("\033[31;1m");
		printf("请输入卡密:");
        char _inputKm[] = "";
	    scanf("%s",&_inputKm);
        FILE *fp = fopen(_kmPath, "w");
        if (fp != NULL) {
            fprintf(fp, "%s", _inputKm);
		    fclose(fp);
        }
        std::cout << "写入成功！正在重新验证卡密" << std::endl;
	}
	fscanf(fopen(_kmPath, "r"), "%s", &_Kami);
	char _Imei[40];
	if (fopen(_imeiPath, "r") == NULL)
	{
		printf("\033[31;1m");
		printf("设备码获取失败\n");
		srand(time(NULL));
        char* _Str = (char*)malloc((20 + 1) * sizeof(char));
        for (int i = 0; i < 20; i++) {
            int _randomNum = rand() % 26;
            _Str[i] = 'a' + _randomNum;
        }
        _Str[20] = '\0';
    
        FILE *fp = fopen(_imeiPath, "w");
        if (fp == NULL) {
            printf("文件创建失败");
            return 0;
        }
        fprintf(fp, "%s", _Str);
        fclose(fp);
        std::cout << "设备码已重新获取！正在重新验证卡密" << std::endl;
	}
	fscanf(fopen(_imeiPath, "r"), "%s", &_Imei);
	printf("卡密： %s\n设备码： %s\n\n", _Kami, _Imei);
	if (_Kami == "" or _Imei == "")
	{
		printf("\033[31;1m");
		printf("无设备码或者卡密");
		return 0;
	}
	time_t _Timet = time(NULL);
	int _Time = time(&_Timet);
    srand(time(NULL));
	char _Value[1024];
	char _Sign[1024];
	char _Data[1024];
	sprintf(_Value, "%d%d", _Time,rand());
	sprintf(_Sign, "kami=%s&markcode=%s&t=%d&%s", _Kami, _Imei, _Time, _wyAppkey);
	unsigned char *_SignData = (unsigned char *)_Sign;
	MD5_CTX md5c;
	MD5Init(&md5c);
	unsigned char _Decrypt[16];
	MD5Update(&md5c, _SignData, strlen((char *)_SignData));
	MD5Final(&md5c, _Decrypt);
	char _SignMd5[33] = { 0 };
	for (int i = 0; i < 16; i++)
	{
		sprintf(&_SignMd5[i * 2], "%02x", _Decrypt[i]);
	}
	sprintf(_Data, "kami=%s&markcode=%s&t=%d&sign=%s&value=%s", _Kami, _Imei, _Time, _SignMd5, _Value);
    char *_enData=Encrypt(_Data, _wyRc4key);
	char _deData[1024];
	sprintf(_deData, "&data=%s", _enData);
	char _deUrl[1024];
	sprintf(_deUrl, "api/?id=kmlogin&app=%s",_wyAppid);
	char *_loginData = httppost(_wyHost,_deUrl,_deData);
	char* _deloginData=Decrypt(_loginData, _wyRc4key);
	cJSON *_loginJson = cJSON_Parse(_deloginData);
	int _loginCode = cJSON_GetObjectItem(_loginJson, "c1509ab2a844ce51deb13f1d2bbe4f48b")->valueint;
	int _loginTime = cJSON_GetObjectItem(_loginJson, "p9b4b6ce3aa0675faab3c81c163b8e40b")->valueint;
	char *_loginMsg = cJSON_GetObjectItem(_loginJson, "ea5faec97260a94d5b4e8223ac6ac72cc")->valuestring;
	char *_loginCheck = cJSON_GetObjectItem(_loginJson, "u384d0fab4629cd666142cdf882b52571")->valuestring;
	if (_loginCode == 49807)
	{
		cJSON *_loginMsgs = cJSON_GetObjectItem(_loginJson, "ea5faec97260a94d5b4e8223ac6ac72cc");
	    char *_checkCode = cJSON_GetObjectItem(_loginMsgs, "w05654020ece8d1ce945d0d22d88daa1c")->valuestring;
		long _loginVip = cJSON_GetObjectItem(_loginMsgs, "qda35efe67608524c9b4a8441d05946ed")->valuedouble;
		long _loginId = cJSON_GetObjectItem(_loginMsgs, "n86d7c03019ee767e6a62b8ee14ed7d34")->valuedouble;
		char _deCheck[1024];
		sprintf(_deCheck, "%d%s%s",_loginTime,_wyAppkey,_Value);
		unsigned char *_deCheckData = (unsigned char *)_deCheck;
		MD5_CTX md5c;
		MD5Init(&md5c);
		unsigned char _Decrypt[16];
		MD5Update(&md5c, _deCheckData, strlen((char *)_deCheckData));
		MD5Final(&md5c, _Decrypt);
		char _checkMd5[33] = { 0 };
		for (int i = 0; i < 16; i++)
		{
			sprintf(&_checkMd5[i * 2], "%02x", _Decrypt[i]);
		}
		if ((string)_checkCode != "4faeaca94edfed1addc93d3115230c0e"){
		    return 0;
		}
		if ((string)_checkMd5 == _loginCheck)
		{
			printf("\033[32;1m");	// 绿色
			printf("登录成功\n");
			if (_loginVip)
			{
				char _vipTime[11];
				sprintf(_vipTime, "%ld", _loginVip);
				time_t _timeStamp = std::atoll(_vipTime);
				std::tm * _timeInfo = std::localtime(&_timeStamp);
				char _buffer[80];
				std::strftime(_buffer, sizeof(_buffer), "%Y-%m-%d %H:%M:%S", _timeInfo);
				std::cout << "到期时间：" << _buffer << std::endl;
				//到期自动退出
				signal(SIGALRM, _exit); 
                alarm(_loginVip-_Time); 
			}
		}
		else
		{
			printf("校验失败\n");
			remove(_kmPath);
		    goto home_main;
		    return 0;
		}
	}
	else
	{
		printf("\033[35;1m");	// 粉红色
		cout << _loginMsg << endl;
		remove(_kmPath);
		goto home_main;
		return 0;
	}





    





    // 创建临时脚本文件
    const char* tempScriptPath = "/data/local/tmp/temp_script.sh";
    std::ofstream scriptFile(tempScriptPath);
    if (scriptFile) {
    //    scriptFile << scriptContent;
        scriptFile.close();

        // 设置脚本为可执行
        std::system(("chmod +x " + std::string(tempScriptPath)).c_str());

        // 执行脚本
        int result = std::system(tempScriptPath);
        if (result != 0) {
            std::cerr << "脚本执行失败，错误码: " << result << std::endl;
        }

        // 删除临时脚本
        remove(tempScriptPath);
    } else {
        std::cerr << "无法创建临时脚本文件" << std::endl;
    }

    system("mkdir -p /data/Atlas配置/配置/ 2>/dev/null");
    
    FILE *file1 = fopen("/data/Atlas配置/配置/", "r");
    if (file1 == NULL) {
        std::ofstream ofs("/data/Atlas配置/配置/");
        ofs.close();
    }

    system("mkdir -p /data/Atlas配置/配置/ 2>/dev/null");

	
	
	
    cout<<"请输入1\n";
    printf("请输入1\n");
    int wht=1;
   cin>>wht;
    if(wht==0){	
    pid_t pid = fork();
    if (pid > 0) {
    exit(0);
    } else if (pid == 0) {  
    } else {
    fprintf(stderr, "创建子进程失败，请联系作者解决问题\n");
    exit(1);
    }
    }
    screen_config();
    ::abs_ScreenX = (::displayInfo.height > ::displayInfo.width ? ::displayInfo.height : ::displayInfo.width);
    ::abs_ScreenY = (::displayInfo.height < ::displayInfo.width ? ::displayInfo.height : ::displayInfo.width);

    ::native_window_screen_x = (displayInfo.height > displayInfo.width ? displayInfo.height : displayInfo.width);
    ::native_window_screen_y = (displayInfo.height > displayInfo.width ? displayInfo.height : displayInfo.width);
    if (init_egl(::native_window_screen_x, ::native_window_screen_y)) {
        ImGui_init();
    } else {
        printf("\033[31;1m"); // 红色
        printf("[!] EGL err\n");
        exit(1);
    }
    Touch::Init({(float)::abs_ScreenX, (float)::abs_ScreenY}, false); // 要想模拟触摸最后一个参数改成 false

    Touch::setOrientation(displayInfo.orientation);
    while (true) {
       drawBegin();
        tick();
        drawEnd();
    }

    shutdown();

    return 0;
}
