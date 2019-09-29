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
���ɲ���ǩ��
argv
DriverPath������·��
return
�ɹ�ΪTRUE��ʧ��ΪFALSE
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

	//��ȡǩ���ļ����ƣ����ں���ṹ����
	WCHAR DriverFileName[MAX_PATH];

	if (Create_Cert())
	{
		Mssign32_handle = LoadLibrary(Mssign32dll);
		if (!Mssign32_handle)
		{
			printf_s("����mssignʧ��\n");
			Ret = FALSE;
			goto Leave;
		}

		//��ȡ���躯��
		farproc_SignerSignEx = (SignerSignExType)GetProcAddress(Mssign32_handle, SignerSignEx);
		farproc_SignerFreeSignerContext = (SignerFreeSignerContextType)GetProcAddress(Mssign32_handle, SignerFreeSignerContext);

		if (!farproc_SignerSignEx || !farproc_SignerFreeSignerContext)
		{
			printf_s("����Sign����ʧ��\n");
			Ret = FALSE;
			goto Leave;
		}

		//���ļ�
		Driver_handle = CreateFileW(DriverPath, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);		//��Ŀ���ļ�
		if (Driver_handle == INVALID_HANDLE_VALUE)
		{
			printf_s("���ļ����ʧ��\n");
			Ret = FALSE;
			goto Leave;
		}

		//�򿪴洢����
		PCertificate_store = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0, CERT_SYSTEM_STORE_LOCAL_MACHINE, Root);
		if (!PCertificate_store)
		{
			printf_s("����֤��ʧ�ܣ���ϵͳ�洢��ʧ�ܣ�%d\n", GetLastError());
			Ret = FALSE;
			goto Leave;
		}

		Cert_Context = CertFindCertificateInStore(PCertificate_store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_SUBJECT_STR, GeekFZ, NULL);	//�ҵ�֮ǰ���ɵ�GeekFZǩ����Ϣ
		if (!Cert_Context)
		{
			printf_s("��֤��ʧ�ܣ��Ҳ���֤����Ϣ��%d\n", GetLastError());
			Ret = FALSE;
			goto Leave;
		}

		memcpy_s(DriverFileName, MAX_PATH, DriverPath, MAX_PATH);
		PathRemoveExtension(DriverFileName);		//ȥ����׺
		PathStripPath(DriverFileName);				//ȥ��·��

													//���ṹ��
		SIGNER_FILE_INFO signerFileInfo;
		signerFileInfo.cbSize = sizeof(SIGNER_FILE_INFO);	//�ṹ���С
		signerFileInfo.pwszFileName = DriverFileName;		//Ҫǩ���ļ�����
		signerFileInfo.hFile = Driver_handle;				//Ҫǩ���ļ����

		SIGNER_SUBJECT_INFO signerSubjectInfo;
		signerSubjectInfo.cbSize = sizeof(SIGNER_SUBJECT_INFO);		//�ṹ���С
		DWORD index = 0;
		signerSubjectInfo.pdwIndex = &index;						//����λ��Ĭ��Ϊ��
		signerSubjectInfo.dwSubjectChoice = 1;						//˵�����ļ�����BLOB��1Ϊ�ļ�
		signerSubjectInfo.pSignerFileInfo = &signerFileInfo;		//ָ��ṹ��SIGNER_FILE_INFO

		SIGNER_CERT_STORE_INFO signerCertStoreInfo;
		signerCertStoreInfo.cbSize = sizeof(SIGNER_CERT_STORE_INFO);	//�ṹ���С
		signerCertStoreInfo.pSigningCert = Cert_Context;				//֤��Ľṹ����Ϣ
		signerCertStoreInfo.dwCertPolicy = 2;							//ѡ����ν�֤����ӵ�ǩ��
		signerCertStoreInfo.hCertStore = NULL;							//��ѡ�����ֱ����NULL

		SIGNER_CERT signerCert;
		signerCert.cbSize = sizeof(SIGNER_CERT);			//�ṹ���С
		signerCert.dwCertChoice = 2;						//ָ��֤��洢�ķ�ʽ
		signerCert.pCertStoreInfo = &signerCertStoreInfo;	//ָ��ṹ��signerCertStoreInfo
		signerCert.hwnd = NULL;								//Ĭ��ΪNULL

		SIGNER_SIGNATURE_INFO signerSignatureInfo;
		signerSignatureInfo.cbSize = sizeof(SIGNER_SIGNATURE_INFO);	//�ṹ���С
		signerSignatureInfo.algidHash = CALG_SHA1;					//����ǩ���õ���hash�㷨
		signerSignatureInfo.dwAttrChoice = 0;						//ָ��ǩ���Ƿ�����֤����
		signerSignatureInfo.pAttrAuthcode = NULL;					//ָ����֤ǩ��������
		signerSignatureInfo.psAuthenticated = NULL;					//���������֤���û��ṩ��������ӵ�ǩ����
		signerSignatureInfo.psUnauthenticated = NULL;				//δ���������֤���û��ṩ��������ӵ�ǩ����

		if (S_OK != farproc_SignerSignEx(0, &signerSubjectInfo, &signerCert, &signerSignatureInfo, NULL, NULL, NULL, NULL, &pSignerContext))
		{
			printf_s("ǩ������SignerSignExʧ��!\n");
			Ret = FALSE;
		}

	}
	else
	{
		Ret = FALSE;
		printf_s("֤����Ϣ����ʧ��\n");
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
����֤����Ϣ
argv
NULL
return
�ɹ�ΪTRUE��ʧ��ΪFALSE
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

	//�ж�ǩ����Ϣ�Ƿ����ɹ�
	if (Check_Cert())
	{
		goto Leave;
	}
	//��������
	if (!CryptAcquireContextW(&phProv, GeekFZ, NULL, PROV_RSA_FULL, CRYPT_MACHINE_KEYSET) && !CryptAcquireContextW(&phProv, GeekFZ, 0, PROV_RSA_FULL, CRYPT_MACHINE_KEYSET | CRYPT_NEWKEYSET))
	{
		printf_s("����֤��ʧ�ܣ�������������ʧ�ܣ�%d\n", GetLastError());
		Ret = FALSE;
		goto Leave;
	}
	//������Կ��
	if (!CryptGenKey(phProv, AT_SIGNATURE, 0x08000000, &phKey))
	{
		printf_s("����֤��ʧ�ܣ���������keyʧ�ܣ�%d\n", GetLastError());
		Ret = FALSE;
		goto Leave;
	}
	//����֤����
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

				//���������֤��
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
					printf_s("����֤��ʧ�ܣ���������֤��ʧ�ܣ�%d\n", GetLastError());
					Ret = FALSE;
					goto Leave;
				}

				//��֤��洢��
				PCertificate_store = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0, CERT_SYSTEM_STORE_LOCAL_MACHINE, Root);
				if (!PCertificate_store)
				{
					printf_s("����֤��ʧ�ܣ���ϵͳ�洢��ʧ�ܣ�%d\n", GetLastError());
					Ret = FALSE;
					goto Leave;
				}

				//�����������֤�鵽֤��洢��
				if (!CertAddCertificateContextToStore(PCertificate_store, Cert_Context, CERT_STORE_ADD_REPLACE_EXISTING, 0))
				{
					printf_s("����֤��ʧ�ܣ����֤�鵽�洢��ʧ�ܣ�%d\n", GetLastError());
					Ret = FALSE;
					goto Leave;
				}

				if (!CryptAcquireCertificatePrivateKey(Cert_Context, 0, NULL, &phCryptProvOrNCryptKey, &pdwKeySpec, &pfCallerFreeProvOrNCryptKey))
				{
					printf_s("����֤��ʧ�ܣ���ȡ��Կʧ�ܣ�%d\n", GetLastError());
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
����֤����Ϣ
argv
NULL
return
�ɹ�ΪTRUE��ʧ��ΪFALSE
*/
BOOL Check_Cert()
{
	BOOL Ret = FALSE;
	HCERTSTORE PCertificate_store;
	PCCERT_CONTEXT PCert_context = NULL;

	PCertificate_store = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0, CERT_SYSTEM_STORE_CURRENT_USER, Root);	//��֤��洢
	if (PCertificate_store)
	{
		//����򿪳ɹ���Ѱ��ǩ����Ϣ
		PCert_context = CertFindCertificateInStore(PCertificate_store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_CERT_ID, GeekFZ, NULL);	//Ѱ��ǩ����Ϣ
		if (PCert_context)
		{
			Ret = TRUE;
		}
	}
	else
	{
		printf_s("��֤��洢�������!\n");
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
