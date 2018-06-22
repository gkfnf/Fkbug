#include "why.h"
#include "ui_why.h"
#include <QStringList>





QString WcharToChar(const TCHAR* wp, size_t codePage = CP_ACP)
{
	QString str;
	int len = WideCharToMultiByte(codePage, 0, wp, wcslen(wp), NULL, 0, NULL, NULL);
	char *p = new char[len + 1];
	memset(p, 0, len + 1);
	WideCharToMultiByte(codePage, 0, wp, wcslen(wp), p, len, NULL, NULL);
	p[len] = '\0';
	str = QString(p);
	delete p;
	p = NULL;
	return str;
}

Why::Why(QWidget *parent) :
	QWidget(parent),
	ui(new Ui::Why)
{
	ui->setupUi(this);

	ui->treeWidget_SectionInfo->setColumnWidth(0, 80);
	ui->treeWidget_SectionInfo->setColumnWidth(1, 60);
	ui->treeWidget_SectionInfo->setColumnWidth(2, 60);
	ui->treeWidget_SectionInfo->setColumnWidth(3, 60);

	ui->treeWidget_ImportInfo->setColumnWidth(0, 180);

	ui->treeWidget_ImportApiInfo->setColumnWidth(0, 200);
	ui->treeWidget_ImportApiInfo->setColumnWidth(1, 50);
	ui->treeWidget_ImportApiInfo->setColumnWidth(2, 50);
	ui->treeWidget_ImportApiInfo->setColumnWidth(3, 50);
	ui->treeWidget_ImportApiInfo->setColumnWidth(4, 30);

	ui->treeWidget_Process->setColumnCount(5);
	ui->treeWidget_Process->setColumnWidth(0, 200);

	ui->treeWidget_Service->setColumnCount(4);
	ui->treeWidget_Service->setColumnWidth(0, 400);
	ui->treeWidget_Service->setColumnWidth(0, 120);
	ui->treeWidget_Service->setColumnWidth(0, 150);

	ui->tabWidget->setCurrentIndex(0);    // if no default index , upon this time drop the file alarms breaking down!

}

Why::~Why()
{
	delete ui;
}





void Why::dragEnterEvent(QDragEnterEvent *event)
{
	if (event->mimeData()->hasUrls())
	{
		//ui->lineEdit_Pe->setText("Is Pe?");
		event->acceptProposedAction();
		event->accept();
	}
}

void Why::dropEvent(QDropEvent *event)
{
	QList<QUrl> urls = event->mimeData()->urls();

	QString* fileName = new QString(urls.first().toLocalFile());

	switch (ui->tabWidget->currentIndex())
	{
		// Page PE:
		case 0:
		{
			TCHAR* szPePath = (TCHAR*)(*fileName).utf16();
			m_PePath = szPePath;
			ui->lineEdit_Pe->setText(*fileName);
			IsPeFile();
			break;
		}
		// Page Virus:
		case 1:
		{
			m_VirusPath = *fileName;
			ui->lineEdit_Virus->setText(m_VirusPath);
			break;
		}
		// Page file:
		case 2:
		{
			//const wchar_t * szGarbagePath = reinterpret_cast<const wchar_t *>(fileName.utf16());
			m_TrashiPathInLineEdit = *fileName;
			ui->lineEdit_Trash->setText(*fileName);		
			break;
		}
	
	
		default:
		{
		break;
		}
	}
}








// PE:

DWORD Why::RvaToOffset(DWORD rva)
{
	PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(m_pNt);
	for (size_t i = 0; i < m_pNt->FileHeader.NumberOfSections; i++)
	{
		if (rva >= pSec[i].VirtualAddress && rva <= pSec[i].VirtualAddress + pSec[i].SizeOfRawData)
		{
			if (pSec[i].SizeOfRawData == 0)
			{
				return 0;
			}
			return rva - pSec[i].VirtualAddress + pSec[i].PointerToRawData;
		}
	}
}

DWORD Why::FoaToRva(DWORD foa)
{
	PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(m_pNt);
	for (size_t i = 0; i < m_pNt->FileHeader.NumberOfSections; i++)
	{
		if (foa >= pSec[i].PointerToRawData && foa <= pSec[i].PointerToRawData + pSec[i].SizeOfRawData)
		{
			if (pSec[i].SizeOfRawData == 0)
			{
				return 0;
			}
			return foa - pSec[i].PointerToRawData + pSec[i].VirtualAddress;
		}
	}
}

DWORD Why::VaToOffset(DWORD Va)
{
	//return Va - m_p + m_OptionHeader->ImageBase;
	return 0;
}

bool Why::IsPeFile()
{
	// 0.Null?
	HANDLE hFile = CreateFile(m_PePath, GENERIC_READ, FILE_SHARE_READ,
	NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		QMessageBox err;
		err.setText("File Error!!!");
		err.exec();
		return false;
	}
	DWORD  dwSize = GetFileSize(hFile, NULL);
	LPBYTE p = new BYTE[dwSize]{};
	ReadFile(hFile, p, dwSize, &dwSize, NULL);

	m_p = p;
	if ((m_p == 0) || (m_p == nullptr))
	{
		QMessageBox err;
		err.setText("Wrong Path!!!");
		err.exec();
		return false;
	}
	CloseHandle(hFile);

	// 1.MZ?
	IMAGE_DOS_HEADER *pDos = (PIMAGE_DOS_HEADER)m_p;
	if (pDos->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return false;
	}
	// 2.PE?
	IMAGE_NT_HEADERS *pNt = (PIMAGE_NT_HEADERS)(m_p + pDos->e_lfanew);
	if (pNt->Signature != IMAGE_NT_SIGNATURE)
	{
		return false;
	}

	m_pNt = pNt;
	m_pFile = (PIMAGE_FILE_HEADER)&pNt->FileHeader;
	m_pOptionHeader = (PIMAGE_OPTIONAL_HEADER)&pNt->OptionalHeader;
	return true;
}

bool Why::PaserPeBaseInfo()
{
	if (!IsPeFile())
	{
		return false;
	}

	ui->lineEdit_3->setText(QString::number(m_pFile->NumberOfSections, 16));
	ui->lineEdit_4->setText(QString::number(m_pFile->TimeDateStamp, 16));
	ui->lineEdit_5->setText(QString::number(m_pFile->Characteristics, 16));
	ui->lineEdit_6->setText(QString::number(m_pOptionHeader->Magic, 16));
	ui->lineEdit_7->setText(QString::number(m_pOptionHeader->AddressOfEntryPoint, 16));
	ui->lineEdit_8->setText(QString::number(m_pOptionHeader->BaseOfCode, 16));
	ui->lineEdit_9->setText(QString::number(m_pOptionHeader->BaseOfData, 16));
	ui->lineEdit_10->setText(QString::number(m_pOptionHeader->ImageBase, 16));
	ui->lineEdit_11->setText(QString::number(m_pOptionHeader->SectionAlignment, 16));
	ui->lineEdit_12->setText(QString::number(m_pOptionHeader->FileAlignment, 16));
	ui->lineEdit_13->setText(QString::number(m_pOptionHeader->SizeOfImage, 16));
	ui->lineEdit_14->setText(QString::number(m_pOptionHeader->SizeOfHeaders, 16));
	ui->lineEdit_15->setText(QString::number(m_pOptionHeader->CheckSum, 16));
	ui->lineEdit_16->setText(QString::number(m_pOptionHeader->Subsystem, 16));
	ui->lineEdit_17->setText(QString::number(m_pOptionHeader->NumberOfRvaAndSizes, 16));
}

void Why::PaserDatadirectory()
{
	if (!IsPeFile())
	{
		return;
	}

	ui->lineEdit_18->setText(QString::number(m_pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, 16));
	ui->lineEdit_19->setText(QString::number(m_pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress, 16));
	ui->lineEdit_20->setText(QString::number(m_pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, 16));
	ui->lineEdit_21->setText(QString::number(m_pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress, 16));
	ui->lineEdit_22->setText(QString::number(m_pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress, 16));
	ui->lineEdit_23->setText(QString::number(m_pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress, 16));
	ui->lineEdit_24->setText(QString::number(m_pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress, 16));
	ui->lineEdit_25->setText(QString::number(m_pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_ARCHITECTURE].VirtualAddress, 16));
	ui->lineEdit_26->setText(QString::number(m_pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_GLOBALPTR].VirtualAddress, 16));
	ui->lineEdit_27->setText(QString::number(m_pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress, 16));
	ui->lineEdit_28->setText(QString::number(m_pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress, 16));
	ui->lineEdit_29->setText(QString::number(m_pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress, 16));
	ui->lineEdit_30->setText(QString::number(m_pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress, 16));
	ui->lineEdit_31->setText(QString::number(m_pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress, 16));
	ui->lineEdit_32->setText(QString::number(m_pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress, 16));
}

void Why::PaserSectionInfo()
{
	QString SectionName;

	PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(m_pNt);
	for (size_t i = 0; i < m_pNt->FileHeader.NumberOfSections; i++)
	{
		QTreeWidgetItem *item = new QTreeWidgetItem(ui->treeWidget_SectionInfo);
		//SectionName = ;
		item->setText(0, QString::fromLocal8Bit((char*)pSec[i].Name, -1)/*SectionName*/);
		item->setText(1, QString::number(pSec[i].PointerToRawData, 16));
		item->setText(2, QString::number(pSec[i].SizeOfRawData, 16));
		item->setText(3, QString::number(pSec[i].SizeOfRawData, 16));
		item->setText(4, QString::number(pSec[i].VirtualAddress, 16));
		item->setText(5, QString::number(pSec[i].Misc.VirtualSize, 16));
	}
}

void Why::PaserExportInfo()
{
	if (m_pNt->FileHeader.Characteristics & IMAGE_FILE_DLL)
	{
		PIMAGE_DATA_DIRECTORY pExportDir = &m_pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		DWORD dwFoA = RvaToOffset(pExportDir->VirtualAddress);
		// EXPORT TABLE's VA：
		PIMAGE_EXPORT_DIRECTORY pExportData = (PIMAGE_EXPORT_DIRECTORY)(m_p + dwFoA);
		// EAT VA:
		PDWORD pEAT_VA = (PDWORD)(m_p + RvaToOffset(pExportData->AddressOfFunctions));
		// ENT VA:
		PDWORD pENT_VA = (PDWORD)(m_p + RvaToOffset(pExportData->AddressOfNames));
		// EOT VA:
		PWORD pEOT_VA = (PWORD)(m_p + RvaToOffset(pExportData->AddressOfNameOrdinals));

		char* fileNameVA = (char*)(RvaToOffset(pExportData->Name) + m_p);
		ui->lineEdit_33->setText(QString::number(pExportData->AddressOfNameOrdinals, 16));
		ui->lineEdit_34->setText(QString::number(pExportData->AddressOfFunctions, 16));
		ui->lineEdit_35->setText(QString::number(pExportData->Characteristics, 10));
		ui->lineEdit_36->setText(QString::number(dwFoA, 16));
		ui->lineEdit_37->setText(QString::number(pExportData->NumberOfFunctions, 10));
		ui->lineEdit_38->setText(QString::number(pExportData->NumberOfNames, 10));
		ui->lineEdit_39->setText(QString::number(pExportData->Name, 16));
		ui->lineEdit_40->setText(QString::number(pExportData->Base, 16));
		ui->lineEdit_41->setText(QString::number(pExportData->AddressOfNames, 16));
		ui->lineEdit_42->setText(QString::fromLocal8Bit(fileNameVA, -1));

		for (size_t i = 0; i < pExportData->NumberOfFunctions; i++)
		{
			QTreeWidgetItem* item = new QTreeWidgetItem(ui->treeWidget_ExportInfo);
			// Ordinal Base
			item->setText(0, QString::number(i + pExportData->Base, 10));
			// Export Addr
			item->setText(1, QString::number(pEAT_VA[i], 16));
			item->setText(2, QString::number(RvaToOffset(pEAT_VA[i]), 16));
			// API Name
			for (size_t j = 0; j < pExportData->NumberOfNames; j++)
			{
				if ((pEOT_VA[j] == i))
				{
					char* FunStr = (char*)(m_p + RvaToOffset(pENT_VA[j]));
					item->setText(3, QString::fromLocal8Bit(FunStr, -1));
				}
			}
		}
		return;
	}
	QMessageBox err;
	err.setIcon(QMessageBox::Critical);
	err.setText("Not a Dll And usually didn't Export Function!!!");
	err.exec();
	return;
}

void Why::PaserImportInfo()
{
	ui->treeWidget_ImportInfo->clear();

	PIMAGE_DATA_DIRECTORY pImportDir = &m_pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	DWORD dwFOA = RvaToOffset(pImportDir->VirtualAddress);
	PIMAGE_IMPORT_DESCRIPTOR pImportData = (PIMAGE_IMPORT_DESCRIPTOR)(m_p + dwFOA);

	while (pImportData->OriginalFirstThunk)
	{
		QTreeWidgetItem* item = new QTreeWidgetItem(ui->treeWidget_ImportInfo);

		// Dll Name
		item->setText(0, QString::fromLocal8Bit((char*)(m_p + RvaToOffset(pImportData->Name)), -1));
		// INT RVA
		item->setText(1, QString::number(pImportData->OriginalFirstThunk, 16));
		// IAT RVA
		item->setText(2, QString::number(pImportData->FirstThunk, 16));
		// str RVA
		item->setText(3, QString::number(pImportData->Name, 16));

		pImportData++;
	}
}

void Why::PaserImportAPIInfo(DWORD OriginalFirstThunk)
{
	ui->treeWidget_ImportApiInfo->clear();

	// Use INT/IAT to Traverse?
	// INT: OriginalFirstThunk     IAT: FirstThunk
	PIMAGE_THUNK_DATA pDataTab = (PIMAGE_THUNK_DATA)(m_p + RvaToOffset(OriginalFirstThunk));

	while (pDataTab->u1.Ordinal)
	{
		QTreeWidgetItem* item = new QTreeWidgetItem(ui->treeWidget_ImportApiInfo);

		// Name/Ordinal?
		if (IMAGE_SNAP_BY_ORDINAL(pDataTab->u1.Ordinal))
		{
			// Import By Oridinal:
			item->setText(0, QString::number(pDataTab->u1.Ordinal & 0xffff));
		}
		else
		{
			// Import By Name:
			PIMAGE_IMPORT_BY_NAME pHintName = (PIMAGE_IMPORT_BY_NAME)(m_p + RvaToOffset(pDataTab->u1.AddressOfData));
			item->setText(0, QString::fromLocal8Bit(pHintName->Name, -1));
			DWORD dwFoa = (DWORD)pDataTab - (DWORD)m_p;
			item->setText(1, QString::number(dwFoa, 16));
			item->setText(2, QString::number(FoaToRva(dwFoa), 16));
			item->setText(3, QString::number(pDataTab->u1.AddressOfData, 16));
			item->setText(4, QString::number(pHintName->Hint, 16));
			item->setText(5, QString::number(pDataTab->u1.Function, 16));

			// printf("%d:%s\n", pHintName->Hint, pHintName->Name);
		}
		pDataTab++;
	}
}

void Why::PaserResourceInfo()
{
	// res Array
	QStringList szRes = { "", "Cursor","Bitmap","icon","Menu","Dialog","Stringlist","FontDir",
					   "font","Shortcuts" , "Untyped_res","Msg_list","CursorGroup","","iconGroup","","Architecture" };

	// res Dir Start Addr:
	PIMAGE_DATA_DIRECTORY pDataDir = &m_pOptionHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];
	PIMAGE_RESOURCE_DIRECTORY pDirFst = (PIMAGE_RESOURCE_DIRECTORY)(RvaToOffset(pDataDir->VirtualAddress) + m_p);

	// Num of rsc type:    Named by Id + Named by Name
	DWORD dwCountKind = pDirFst->NumberOfIdEntries + pDirFst->NumberOfNamedEntries;

	// First Level rsc struct Array's Start Addr:
	PIMAGE_RESOURCE_DIRECTORY_ENTRY  pDataFst = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pDirFst + 1);// Do not ++！！！

	for (int i = 0; i < dwCountKind; i++)
	{
		QTreeWidgetItem* itemLevel1 = NULL;
		
		// rsc Named by Name: res is Unknowned type, using IMAGE_RESOURCE_DIR_STRING_U->NameString to Describe the res type;
		
		if (pDataFst[i].NameIsString)
		{
			// Find Name Offset:
			PIMAGE_RESOURCE_DIR_STRING_U pNameU = (PIMAGE_RESOURCE_DIR_STRING_U)(pDataFst[i].NameOffset + (DWORD)pDirFst);

			// Get TypeName:
			WCHAR *pTypeName = new WCHAR[pNameU->Length + 1]{};
			memcpy_s(pTypeName, sizeof(WCHAR)*pNameU->Length, pNameU->NameString, sizeof(WCHAR)*pNameU->Length);

			itemLevel1 = new QTreeWidgetItem(ui->treeWidget_Rsc);
			itemLevel1->setText(0, QString::fromWCharArray(pTypeName));

			delete[] pTypeName;
		}
		// rsc Named by ID: Knowed res type, Using Id as szRes's cursor;
		else
		{
			itemLevel1 = new QTreeWidgetItem(ui->treeWidget_Rsc);

			// Standard type:
			if ((pDataFst[i].Id >= 1 && pDataFst[i].Id <= 12) ||
				pDataFst[i].Id == 14 || pDataFst[i].Id == 16)
			{
				itemLevel1->setText(0, szRes.at(pDataFst[i].Id));
			}
			else
			{
				// Not Standard type: display id
				itemLevel1->setText(0, QString::number(pDataFst[i].Id, 10));
			}
		}
		// Second Level rsc struct Array's Start Addr:
		PIMAGE_RESOURCE_DIRECTORY pDirSec = (PIMAGE_RESOURCE_DIRECTORY)(pDataFst[i].OffsetToDirectory + (DWORD)pDirFst);

		// Second Level Represented Nums of that kind res:
		DWORD dwCountOfThatKind = pDirSec->NumberOfIdEntries + pDirSec->NumberOfNamedEntries;
		// Second Level's res Entry Struct's Start Addr
		PIMAGE_RESOURCE_DIRECTORY_ENTRY pDataSec = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pDirSec + 1);

		for (int j = 0; j < dwCountOfThatKind; j++)
		{
			QTreeWidgetItem* itemLevel2 = NULL;
			// this res is Named by Id or string
			if (pDataSec[j].NameIsString)
			{
				// find name:
				PIMAGE_RESOURCE_DIR_STRING_U pNameU = (PIMAGE_RESOURCE_DIR_STRING_U)(pDataSec[j].NameOffset + (DWORD)pDirFst);
				WCHAR *pName = new WCHAR[pNameU->Length + 1]{};
				memcpy_s(pName, sizeof(WCHAR)*pNameU->Length, pNameU->NameString, sizeof(WCHAR)*pNameU->Length);

				itemLevel2 = new QTreeWidgetItem(itemLevel1);
				itemLevel2->setText(1, QString::fromWCharArray(pName));
				itemLevel1->addChild(itemLevel2);
				delete[] pName;
			}
			else
			{
				itemLevel2 = new QTreeWidgetItem(itemLevel1);
				itemLevel2->setText(1, QString::number(pDataSec[j].Id, 10));
			}

			// Last (3) Level:
			PIMAGE_RESOURCE_DIRECTORY pDirThr = (PIMAGE_RESOURCE_DIRECTORY)((DWORD)pDirFst + pDataSec[j].OffsetToDirectory);
			// Data:
			PIMAGE_RESOURCE_DIRECTORY_ENTRY pDataThr = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pDirThr + 1);

			// CodePage:
			QTreeWidgetItem* itemLevel3 = new QTreeWidgetItem(itemLevel2);
			itemLevel3->setText(0, QString::number(pDataThr->Name, 10));
			// printf("|---|---|---代码页%d\n", pDataThr->Name);

			// res detailinfo offset:
			itemLevel3->setText(1, QString::number(pDataThr->OffsetToData, 16));
			//printf("|---|---|---资源信息偏移%d\n", pDataThr->OffsetToData);
			// Last Info:
			PIMAGE_RESOURCE_DATA_ENTRY pLast = (PIMAGE_RESOURCE_DATA_ENTRY)(pDataThr->OffsetToData + (DWORD)pDirFst);

			QTreeWidgetItem* itemLevelData = new QTreeWidgetItem(itemLevel3);
			itemLevelData->setText(0, QString::number(pLast->OffsetToData, 16));
			itemLevelData->setText(1, QString::number(pLast->Size, 16));
			//printf("|---|---|---|---资源RVA:%08x\n", pLast->OffsetToData);
			//printf("|---|---|---|---资源Size:%08x\n", pLast->Size);
		}
	}
}








// File:/

bool Why::DelDir(const QString & path)
{
	QStringList fileList;
	QString filter;

	// Traverse the File dir，Saving to file_info_list:
	QFileInfoList file_info_list = GetFileList(path);

	// Traverse the file_info_list and compare the suffix and the file's attribute

	foreach(QFileInfo fileinfo, file_info_list)
	{
		// when del way is sys or IE just clear file
		if ((m_delWay == 1) || (m_delWay == 2))
		{
			fileinfo.dir().remove(fileinfo.fileName());
			QString deltedFile = fileinfo.fileName();
			QString deltedDir = fileinfo.filePath();
			if (fileinfo.isDir())
			{
				ui->listWidget_Trash->addItem("del" + deltedDir + deltedFile + '/');
				break;
			}
			ui->listWidget_Trash->addItem("deleted " + deltedDir);
			break;
		}


		//_filter = _fileinfo.completeSuffix();

		filter = fileinfo.suffix();

		// 		for (int i = 0; i < m_FileExtentionListArray.size(); i++)
		// 		{
		for (int j = 0; j < m_CustomTrashSuffix.size(); j++)
		{
			

			    if (filter == m_CustomTrashSuffix.at(j))              // file need deleted in suffix array
			    {
				fileinfo.dir().remove(fileinfo.fileName());
				QString deltedFile = fileinfo.fileName();
				QString deltedDir = fileinfo.filePath();
				if (fileinfo.isDir())
				{
					ui->listWidget_Trash->addItem("del" + deltedDir + deltedFile + '/');
				}
					ui->listWidget_Trash->addItem("deleted " + deltedDir);
				// 				}
				// 			}
			}
			//fileList.append(fileinfo.absoluteFilePath());
		}

	}
	return false;
}




// Be Careful !!!    Qdir's default construct func is current path(this program) !!!!
// So if the path is null
// this dir will constructed  by this program's path, and delete it will delete the code.
QFileInfoList Why::GetFileList(QString path)
{
	QDir dir(path);
	QFileInfoList file_list = dir.entryInfoList(QDir::Files | QDir::Hidden | QDir::NoSymLinks);
	QFileInfoList folder_list = dir.entryInfoList(QDir::Dirs | QDir::NoDotAndDotDot);

	for (int i = 0; i != folder_list.size(); i++)
	{
		QString name = folder_list.at(i).absoluteFilePath();
		QFileInfoList child_file_list = GetFileList(name);
		file_list.append(child_file_list);
	}
	return file_list;
}










// Service And Window:

void Why::TraverseService()
{
	LONG lRet = 0;
	BOOL bRet = FALSE;
	SC_HANDLE hSCM = NULL;              // Service database HANDLE
	char *pBuf = NULL;                  // buffer's pointer
	DWORD dwBufSize = 0;
	DWORD dwBufNeed = 0;
	DWORD dwNumberOfService = 0;
	ENUM_SERVICE_STATUS_PROCESS *pServiceInfo = NULL;   // Service Info

	hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE | SC_MANAGER_CONNECT);
	if (NULL == hSCM)
	{
		printf("OpenSCManager error.\n");
		return;
	}

	// Get Buffer size first
	EnumServicesStatusEx(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
		NULL, dwBufSize, &dwBufNeed, &dwNumberOfService, NULL, NULL);

	dwBufSize = dwBufNeed + sizeof(ENUM_SERVICE_STATUS_PROCESS);
	pBuf = (char *)malloc(dwBufSize);
	if (NULL == pBuf)
	{
		printf("malloc error.\n");
		return;
	}
	memset(pBuf, 0, dwBufSize);

	// Get Service Info
	bRet = EnumServicesStatusEx(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
		(LPBYTE)pBuf, dwBufSize, &dwBufNeed, &dwNumberOfService, NULL, NULL);
	if (bRet == FALSE)
	{
		printf("EnumServicesStatusEx error.\n");
		::CloseServiceHandle(hSCM);
		free(pBuf);
		return;
	}
	// Close Service HANDLE
	bRet = ::CloseServiceHandle(hSCM);
	if (bRet == FALSE)
	{
		//printf("CloseServiceHandle error.\n");
	}
	//printf("Service Num:%d\n", dwNumberOfService);

	pServiceInfo = (LPENUM_SERVICE_STATUS_PROCESS)pBuf;

	for (DWORD i = 0; i < dwNumberOfService; i++)
	{
		QTreeWidgetItem* item = new QTreeWidgetItem(ui->treeWidget_Service);

		SC_HANDLE hService = OpenService(hSCM, pServiceInfo[i].lpServiceName, SERVICE_QUERY_CONFIG);

		// first get buff size and allocate buff
		QueryServiceConfig(hService, NULL, 0, &dwBufSize);
		LPQUERY_SERVICE_CONFIG pServiceConfig = (LPQUERY_SERVICE_CONFIG)new char[dwBufSize];

		// Get Information
		QueryServiceConfig(hService, pServiceConfig, dwBufSize, &dwBufSize);

		item->setText(0, QString::fromUtf16((unsigned short*)pServiceInfo[i].lpServiceName, -1));
		item->setText(1, QString::number(pServiceInfo[i].ServiceStatusProcess.dwCurrentState, 10));

		switch (pServiceInfo[i].ServiceStatusProcess.dwCurrentState)
		{
		case SERVICE_CONTINUE_PENDING: {item->setText(1, "SERVICE_CONTINUE_PENDING"); } break;
		case SERVICE_PAUSE_PENDING: {item->setText(1, "SERVICE_PAUSE_PENDING"); } break;
		case SERVICE_PAUSED: {item->setText(1, "SERVICE_PAUSED"); } break;
		case SERVICE_RUNNING: {item->setText(1, "SERVICE_RUNNING"); } break;
		case SERVICE_START_PENDING: {item->setText(1, "SERVICE_START_PENDING"); } break;
		case SERVICE_STOP_PENDING: {item->setText(1, "SERVICE_STOP_PENDING"); } break;
		case SERVICE_STOPPED: {item->setText(1, "SERVICE_STOPPED"); } break;
		}
		switch (pServiceInfo[i].ServiceStatusProcess.dwServiceType)
		{
		case SERVICE_FILE_SYSTEM_DRIVER: {item->setText(2, "SERVICE_FILE_SYSTEM_DRIVER"); } break;
		case SERVICE_KERNEL_DRIVER: {item->setText(2, "SERVICE_KERNEL_DRIVER"); } break;
		case SERVICE_WIN32_OWN_PROCESS: {item->setText(2, "SERVICE_WIN32_OWN_PROCESS"); } break;
		case SERVICE_WIN32_SHARE_PROCESS: {item->setText(2, "SERVICE_WIN32_SHARE_PROCESS"); } break;
		case SERVICE_INTERACTIVE_PROCESS: {item->setText(2, "SERVICE_INTERACTIVE_PROCESS"); } break;
		}
		switch (pServiceConfig->dwStartType)
		{
		case SERVICE_AUTO_START: {item->setText(3, "AUTO_START"); } break;

		case SERVICE_BOOT_START: {item->setText(3, "BOOT_START"); } break;

		case SERVICE_DEMAND_START: {item->setText(3, "DEMAND_START"); } break;

		case SERVICE_DISABLED: {item->setText(3, "DISABLED"); } break;

		case SERVICE_SYSTEM_START: {item->setText(3, "SYSTEM_START"); } break;
		}
		//item->setText(3, QString::number(pServiceConfig->dwStartType, 10));

		// QString fromUtf16(const ushort * unicode, int size = -1)

		// item->setText(4, QString::fromUtf16( (unsigned short*)(pServiceConfig->lpBinaryPathName), -1));
	}
}









// Process:

void Why::TraverseProcess()
{
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (INVALID_HANDLE_VALUE == hProcessSnap)
	{
		QMessageBox err;
		err.setIcon(QMessageBox::Critical);
		err.setText("创建进程快照失败");
		err.exec();

		return;
	}

	PROCESSENTRY32 processInfo;

	processInfo.dwSize = sizeof(processInfo);

	Process32First(hProcessSnap, &processInfo);

	do
	{
		QTreeWidgetItem* item = new QTreeWidgetItem(ui->treeWidget_Process);

		item->setText(0, QString::fromWCharArray(processInfo.szExeFile));
		item->setText(1, QString::number(processInfo.th32ProcessID));
		item->setText(2, QString::number(processInfo.cntThreads));
		item->setText(3, QString::number(processInfo.pcPriClassBase));
		item->setText(4, QString::number(processInfo.th32ParentProcessID));
		item->setText(5, QString::number(processInfo.th32DefaultHeapID));
	} while (Process32Next(hProcessSnap, &processInfo));
}

bool Why::KillProcess(DWORD dwProcessID)
{
	HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, dwProcessID);
	TerminateProcess(hProcess, 1);
	CloseHandle(hProcess);
	return true;
}

void Why::TraverseThread(DWORD dwPid)
{
	ui->treeWidget_Thread->clear();

	HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

	if (INVALID_HANDLE_VALUE == hThreadSnap)
	{
		QMessageBox err;
		err.setIcon(QMessageBox::Critical);
		err.setText("Create Process Snap failure!!!");
		err.exec();

		return;
	}

	THREADENTRY32 threadInfo;

	threadInfo.dwSize = sizeof(threadInfo);

	Thread32First(hThreadSnap, &threadInfo);

	do
	{
		if (threadInfo.th32OwnerProcessID == dwPid)
		{
			QTreeWidgetItem* item = new QTreeWidgetItem(ui->treeWidget_Thread);
			item->setText(0, QString::number(threadInfo.th32ThreadID, 10));
			item->setText(1, QString::number(threadInfo.tpBasePri, 10));
			item->setText(2, QString::number(threadInfo.tpDeltaPri, 10));
		}
	} while (Thread32Next(hThreadSnap, &threadInfo));

	return;
}

bool Why::SuspendThread(DWORD dwThreadID)
{
	HANDLE hThread = OpenThread(THREAD_TERMINATE, FALSE, dwThreadID);
	TerminateThread(hThread, 1);
	CloseHandle(hThread);
	return true;
}

void Why::TraverseModule(DWORD dwPid)
{
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, dwPid);

	if (hProcess == INVALID_HANDLE_VALUE)
		return;

	HMODULE* phModuleArray = nullptr;
	DWORD    dwCountSize = 0;

	if (0 == EnumProcessModulesEx(hProcess, 0, 0, &dwCountSize, LIST_MODULES_ALL))
		return;

	phModuleArray = new HMODULE[dwCountSize / sizeof(HMODULE)];

	if (0 == EnumProcessModulesEx(hProcess, phModuleArray, dwCountSize, &dwCountSize, LIST_MODULES_ALL))
		return;

	TCHAR szModuleName[MAX_PATH];
	TCHAR szModulePath[MAX_PATH];

	for (int i = 0; i < dwCountSize / sizeof(HMODULE); ++i)
	{
		MODULEINFO stcModuleInfo = { 0 };
		GetModuleBaseName(hProcess, phModuleArray[i], szModuleName, MAX_PATH);
		GetModuleFileNameEx(hProcess, phModuleArray[i], szModulePath, MAX_PATH);
		GetModuleInformation(hProcess, phModuleArray[i], &stcModuleInfo, sizeof(MODULEINFO));

		QTreeWidgetItem* item = new QTreeWidgetItem(ui->treeWidget_Module);
		item->setText(0, QString::fromWCharArray(szModuleName));
		item->setText(1, QString::fromWCharArray(szModulePath));
		item->setText(4, QString::number((DWORD)stcModuleInfo.lpBaseOfDll, 16));
		item->setText(5, QString::number(stcModuleInfo.SizeOfImage, 16));

		//                }
		//            }
		//     }while(Module32Next(hModuleSnap, &myModuleInfo));

		return;
	}
}











// slot:

void Why::on_pushButton_PeAnalysis_clicked()
{
	if (!PaserPeBaseInfo())
	{
		QMessageBox err;
		err.setText(u8"文件路径错误，PE分析失败!!!");
		err.exec();
		return;
	}
	PaserDatadirectory();
	PaserSectionInfo();
	PaserExportInfo();
	PaserImportInfo();
	PaserResourceInfo();
}

void Why::on_treeWidget_ImportInfo_itemClicked(QTreeWidgetItem *item, int column)
{
	bool ok;
	QString INT_RVA = item->text(1);
	DWORD OriginalFirstThunk = INT_RVA.toULong(&ok, 16);

	if (!ok)
	{
		QMessageBox err;
		err.setIcon(QMessageBox::Critical);
		err.setText("Wrong INT RVA!!!");
		err.exec();
	}

	PaserImportAPIInfo(OriginalFirstThunk);
}

void Why::on_treeWidget_Process_itemClicked(QTreeWidgetItem *item, int column)
{
	bool ok;
	QString Str = item->text(1);
	DWORD PID = DWORD(Str.toULong(&ok, 10));

	// 	ui->treeWidget_Process->clear();
	ui->treeWidget_Module->clear();
	ui->treeWidget_Thread->clear();
	TraverseThread(PID);
	TraverseModule(PID);
}

// change tabWidget

void Why::on_tabWidget_currentChanged(int index)
{
	switch (index)
	{
	case 4: // service and windows
	{
		TraverseService();
		break;
	}
	case 5: // process
	{
		TraverseProcess();
		break;
	}
	}
}

// Clear file

void Why::on_pushButton_Clear_clicked()
{
	m_CustomTrashPath.clear();
	m_CustomTrashSuffix.clear();

	switch (m_delWay)
	{
		case 1:  // on checkbox Sys
		{
		m_CustomTrashPath += {  "C:\\Windows\\Temp", "C:\\Windows\\SoftwareDistribution\\Download",
                                "C:\\inetpub", "C:\\ProgramData\\SoftwareDistribution",
                                "C:\\ProgramData\\Package Cache","C:\\Temp" ,
                                "C:\\Windows\\Prefetch", "C:\\Users\\kevin\\AppData\\Local\\Temp",
                                "C:\\Users\\kevin\\AppData\\Local\\Microsoft\\Windows\\WER\\ReportQueue" };
		}break;
		case 2: // on checkbox IE
		{
		m_CustomTrashPath  += { "C:\\Users\\x\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cache" ,
								"C:\\Documents and Settings\\Administrator\\Local Settings\\Temporary Internet Files"};
		
		}break;
		case 3: // on checkbox VS
		{
		
		m_CustomTrashSuffix += { "pdb", "ipdb", "obj", "sdf", "db",
								"log", "tlog", "ipch", "txt",
								"pch", "pbd", "ilk", "lastbuildstate"
							   };
		m_CustomTrashPath.push_back(m_TrashiPathInLineEdit);
		//QStringList m_CustomTrashPath = {};
		break;
		}

	}


	for (int i = 0; i < m_CustomTrashPath.size(); i++)
	{
		DelDir(m_CustomTrashPath.at(i));
	}
	
}



// Clear Ways

void Why::on_radioButton_4_clicked()
{
    m_delWay = 1;
}

void Why::on_radioButton_3_clicked()
{
    m_delWay = 2;
}

void Why::on_radioButton_2_clicked()
{
    m_delWay = 3;
}
// 
// BOOL RegisterHotKey(HWND hWnd, int id, UINT fsModifiers, UINT vk)
// {
// 	return 0;
// }
