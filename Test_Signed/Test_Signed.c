#include"Test_Signed.h"

#define Mssign32dll L"Mssign32.dll"
#define SignerSignEx "SignerSignEx"
#define SignerFreeSignerContext "SignerFreeSignerContext"
#define SignerTimeStampEx "SignerTimeStampEx"
#define pszX500 L"CN=GeekFZ"
#define GeekFZ L"GeekFZ"
#define Root L"Root"

int _tmain(int argc, TCHAR* argv[])
{
	if (Signed(argv[1]))
	{
		printf_s("Signed Driver success!!\n");
	}
	else
	{
		printf_s("Signed Driver fail!!\n");
	}

	return 0;
}

/*
function
生成测试签名
argv
DriverPath：驱动路径
return
成功为TRUE，失败为FALSE
*/
BOOL Signed(LPCWSTR DriverPath)
{
	BOOL Ret = TRUE;
	HANDLE Driver_handle = NULL;
	HMODULE Mssign32_handle = NULL;
	HCERTSTORE PCertificate_store = NULL;
	PCCERT_CONTEXT Cert_Context = NULL;
	SIGNER_CONTEXT * pSignerContext = NULL;
	FARPROC farproc_SignerSignEx = NULL;
	FARPROC farproc_SignerFreeSignerContext = NULL;

	//获取签名文件名称，用于后面结构体中
	WCHAR DriverFileName[MAX_PATH];

	if (Create_Cert())
	{
		Mssign32_handle = LoadLibrary(Mssign32dll);
		if (!Mssign32_handle)
		{
			printf_s("加载mssign失败\n");
			Ret = FALSE;
			goto Leave;
		}

		//获取所需函数
		farproc_SignerSignEx = (SignerSignExType)GetProcAddress(Mssign32_handle, SignerSignEx);
		farproc_SignerFreeSignerContext = (SignerFreeSignerContextType)GetProcAddress(Mssign32_handle, SignerFreeSignerContext);

		if (!farproc_SignerSignEx || !farproc_SignerFreeSignerContext)
		{
			printf_s("加载Sign函数失败\n");
			Ret = FALSE;
			goto Leave;
		}

		//打开文件
		Driver_handle = CreateFileW(DriverPath, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);		//打开目标文件
		if (Driver_handle == INVALID_HANDLE_VALUE)
		{
			printf_s("打开文件句柄失败\n");
			Ret = FALSE;
			goto Leave;
		}

		//打开存储区域
		PCertificate_store = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0, CERT_SYSTEM_STORE_LOCAL_MACHINE, Root);
		if (!PCertificate_store)
		{
			printf_s("创建证书失败，打开系统存储区失败：%d\n", GetLastError());
			Ret = FALSE;
			goto Leave;
		}

		Cert_Context = CertFindCertificateInStore(PCertificate_store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_SUBJECT_STR, GeekFZ, NULL);	//找到之前生成的GeekFZ签名信息
		if (!Cert_Context)
		{
			printf_s("打开证书失败，找不到证书信息：%d\n", GetLastError());
			Ret = FALSE;
			goto Leave;
		}

		memcpy_s(DriverFileName, MAX_PATH, DriverPath, MAX_PATH);
		PathRemoveExtension(DriverFileName);		//去掉后缀
		PathStripPath(DriverFileName);				//去掉路径

													//填充结构体
		SIGNER_FILE_INFO signerFileInfo;
		signerFileInfo.cbSize = sizeof(SIGNER_FILE_INFO);	//结构体大小
		signerFileInfo.pwszFileName = DriverFileName;		//要签名文件名称
		signerFileInfo.hFile = Driver_handle;				//要签名文件句柄

		SIGNER_SUBJECT_INFO signerSubjectInfo;
		signerSubjectInfo.cbSize = sizeof(SIGNER_SUBJECT_INFO);		//结构体大小
		DWORD index = 0;
		signerSubjectInfo.pdwIndex = &index;						//保留位，默认为零
		signerSubjectInfo.dwSubjectChoice = 1;						//说明是文件还是BLOB，1为文件
		signerSubjectInfo.pSignerFileInfo = &signerFileInfo;		//指向结构体SIGNER_FILE_INFO

		SIGNER_CERT_STORE_INFO signerCertStoreInfo;
		signerCertStoreInfo.cbSize = sizeof(SIGNER_CERT_STORE_INFO);	//结构体大小
		signerCertStoreInfo.pSigningCert = Cert_Context;				//证书的结构体信息
		signerCertStoreInfo.dwCertPolicy = 2;							//选择如何将证书添加到签名
		signerCertStoreInfo.hCertStore = NULL;							//可选项，这里直接填NULL

		SIGNER_CERT signerCert;
		signerCert.cbSize = sizeof(SIGNER_CERT);			//结构体大小
		signerCert.dwCertChoice = 2;						//指定证书存储的方式
		signerCert.pCertStoreInfo = &signerCertStoreInfo;	//指向结构体signerCertStoreInfo
		signerCert.hwnd = NULL;								//默认为NULL

		SIGNER_SIGNATURE_INFO signerSignatureInfo;
		signerSignatureInfo.cbSize = sizeof(SIGNER_SIGNATURE_INFO);	//结构体大小
		signerSignatureInfo.algidHash = CALG_SHA1;					//数据签名用到的hash算法
		signerSignatureInfo.dwAttrChoice = 0;						//指定签名是否有验证属性
		signerSignatureInfo.pAttrAuthcode = NULL;					//指定验证签名的属性
		signerSignatureInfo.psAuthenticated = NULL;					//经过身份验证的用户提供的属性添加到签名中
		signerSignatureInfo.psUnauthenticated = NULL;				//未经过身份验证的用户提供的属性添加到签名中

		if (S_OK != farproc_SignerSignEx(0, &signerSubjectInfo, &signerCert, &signerSignatureInfo, NULL, NULL, NULL, NULL, &pSignerContext))
		{
			printf_s("签名函数SignerSignEx失败!\n");
			Ret = FALSE;
		}

	}
	else
	{
		Ret = FALSE;
		printf_s("证书信息加载失败\n");
	}

Leave:
	if (pSignerContext)
	{
		farproc_SignerFreeSignerContext(pSignerContext);
	}
	if (Cert_Context)
	{
		CertFreeCertificateContext(Cert_Context);
	}
	if (PCertificate_store)
	{
		CertCloseStore(PCertificate_store, CERT_CLOSE_STORE_CHECK_FLAG);
	}
	if (Driver_handle)
	{
		CloseHandle(Driver_handle);
	}
	if (Mssign32_handle)
	{
		FreeLibrary(Mssign32_handle);
	}

	return Ret;
}

/*
fucntion
生成证书信息
argv
NULL
return
成功为TRUE，失败为FALSE
*/
BOOL Create_Cert()
{
	BOOL Ret = TRUE;
	BOOL pfCallerFreeProvOrNCryptKey = 0;
	HCRYPTPROV phProv = 0;
	HCRYPTKEY phKey = 0;
	HCERTSTORE PCertificate_store = NULL;
	PCCERT_CONTEXT Cert_Context = NULL;
	HCRYPTPROV_OR_NCRYPT_KEY_HANDLE phCryptProvOrNCryptKey = 0;
	DWORD pdwKeySpec;
	DWORD pcbEncoded = 0;
	BYTE *pbEncoded = NULL;
	//LPCTSTR pszX500 = L"CN=GeekFZ";

	//判断签名信息是否生成过
	if (Check_Cert())
	{
		goto Leave;
	}
	//创建容器
	if (!CryptAcquireContextW(&phProv, GeekFZ, NULL, PROV_RSA_FULL, CRYPT_MACHINE_KEYSET) && !CryptAcquireContextW(&phProv, GeekFZ, 0, PROV_RSA_FULL, CRYPT_MACHINE_KEYSET | CRYPT_NEWKEYSET))
	{
		printf_s("创建证书失败，创建加密容器失败：%d\n", GetLastError());
		Ret = FALSE;
		goto Leave;
	}
	//生成秘钥对
	if (!CryptGenKey(phProv, AT_SIGNATURE, 0x08000000, &phKey))
	{
		printf_s("创建证书失败，创建加密key失败：%d\n", GetLastError());
		Ret = FALSE;
		goto Leave;
	}
	//生成证书名
	if (CertStrToNameW(X509_ASN_ENCODING, pszX500, CERT_X500_NAME_STR, NULL, pbEncoded, &pcbEncoded, NULL))
	{
		pbEncoded = (BYTE *)VirtualAlloc(NULL, sizeof(DWORD), MEM_COMMIT | MEM_TOP_DOWN, PAGE_READWRITE);
		if (pbEncoded)
		{
			if (CertStrToNameW(X509_ASN_ENCODING, pszX500, CERT_X500_NAME_STR, NULL, pbEncoded, &pcbEncoded, NULL))
			{
				CERT_NAME_BLOB SubjectIssuerBlob;
				memset(&SubjectIssuerBlob, 0, sizeof(SubjectIssuerBlob));
				SubjectIssuerBlob.cbData = pcbEncoded;
				SubjectIssuerBlob.pbData = pbEncoded;

				CRYPT_KEY_PROV_INFO KeyProvInfo;
				KeyProvInfo.pwszContainerName = GeekFZ;
				KeyProvInfo.pwszProvName = NULL;
				KeyProvInfo.dwProvType = PROV_RSA_FULL;
				KeyProvInfo.dwFlags = CRYPT_MACHINE_KEYSET;
				KeyProvInfo.cProvParam = 0;
				KeyProvInfo.rgProvParam = NULL;
				KeyProvInfo.dwKeySpec = AT_SIGNATURE;

				CRYPT_ALGORITHM_IDENTIFIER SignatureAlgorithm;
				memset(&SignatureAlgorithm, 0, sizeof(SignatureAlgorithm));
				SignatureAlgorithm.pszObjId = szOID_RSA_SHA1RSA;

				SYSTEMTIME SystemTime;
				GetSystemTime(&SystemTime);
				SystemTime.wYear += 5;

				//创建自身的证书
				Cert_Context = CertCreateSelfSignCertificate(
					0,
					&SubjectIssuerBlob,
					0,
					&KeyProvInfo,
					&SignatureAlgorithm,
					0,
					&SystemTime,
					0);
				if (!Cert_Context)
				{
					printf_s("创建证书失败，创建自身证书失败：%d\n", GetLastError());
					Ret = FALSE;
					goto Leave;
				}

				//打开证书存储区
				PCertificate_store = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0, CERT_SYSTEM_STORE_LOCAL_MACHINE, Root);
				if (!PCertificate_store)
				{
					printf_s("创建证书失败，打开系统存储区失败：%d\n", GetLastError());
					Ret = FALSE;
					goto Leave;
				}

				//添加自身创建的证书到证书存储区
				if (!CertAddCertificateContextToStore(PCertificate_store, Cert_Context, CERT_STORE_ADD_REPLACE_EXISTING, 0))
				{
					printf_s("创建证书失败，添加证书到存储区失败：%d\n", GetLastError());
					Ret = FALSE;
					goto Leave;
				}

				if (!CryptAcquireCertificatePrivateKey(Cert_Context, 0, NULL, &phCryptProvOrNCryptKey, &pdwKeySpec, &pfCallerFreeProvOrNCryptKey))
				{
					printf_s("创建证书失败，获取密钥失败：%d\n", GetLastError());
					Ret = FALSE;
					goto Leave;
				}

				Ret = TRUE;
				goto Leave;
			}
		}
	}

Leave:
	if (phKey)
	{
		CryptDestroyKey(phKey);
	}
	if (phProv)
	{
		CryptReleaseContext(phProv, 0);
	}
	if (pbEncoded)
	{
		VirtualFree(pbEncoded, 0, MEM_RELEASE);
	}
	if (phCryptProvOrNCryptKey)
	{
		CryptReleaseContext(phCryptProvOrNCryptKey, 0);
	}
	if (Cert_Context)
	{
		CertFreeCertificateContext(Cert_Context);
	}
	if (PCertificate_store)
	{
		CertCloseStore(PCertificate_store, 0);
	}

	return Ret;
}

/*
fucntion
生成证书信息
argv
NULL
return
成功为TRUE，失败为FALSE
*/
BOOL Check_Cert()
{
	BOOL Ret = FALSE;
	HCERTSTORE PCertificate_store;
	PCCERT_CONTEXT PCert_context = NULL;

	PCertificate_store = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0, CERT_SYSTEM_STORE_CURRENT_USER, Root);	//打开证书存储
	if (PCertificate_store)
	{
		//如果打开成功则寻找签名信息
		PCert_context = CertFindCertificateInStore(PCertificate_store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_CERT_ID, GeekFZ, NULL);	//寻找签名信息
		if (PCert_context)
		{
			Ret = TRUE;
		}
	}
	else
	{
		printf_s("打开证书存储区域错误!\n");
	}

	if (PCert_context)
	{
		CertFreeCertificateContext(PCert_context);
	}
	if (PCertificate_store)
	{
		CertCloseStore(PCertificate_store, 0);
	}

	return Ret;
}
