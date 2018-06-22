#ifndef WHY_H
#define WHY_H
#include <Windows.h>
#include <QWidget>
#include <QFileInfoList>
#include <QDir>
#include "QMimeData"
#include <QDragEnterEvent>
#include <QDropEvent>
#include <Psapi.h>
#include <QList>
#include <TlHelp32.h>
#include "ShlObj.h"
#include <QMessageBox>
#include <QStringlist>
#include <QTreeWidget>
#include <QTreeWidgetItem>
#include <QMenu>
#pragma comment(lib, "Psapi.lib")
#include <QtNetwork/QLocalServer>
#include <QCryptographicHash>
#include <QByteArray>


// QByteArray GetFileMd5()
// {
// 	HANDLE hFile = CreateFile("")
//     QCryptographicHash::Md5()
// 
// }

// ATOM GlobalAddAtom
// GlobalDeleteAtom


//BOOL RegisterHotKey(HWND hWnd, int id, UINT fsModifiers, UINT vk);




namespace Ui {
	class Why;
}

struct MyModuleInfo
{
	TCHAR  baseName[MAX_PATH];        // Module Name
	TCHAR  dllPath[MAX_PATH];         // Module Path
	MODULEINFO otherModuleInfo;       // Module Info
};


class Why : public QWidget
{
	Q_OBJECT

public:
	explicit Why(QWidget *parent = 0);
	~Why();
protected:
	virtual void dragEnterEvent(QDragEnterEvent *event);
	virtual void dropEvent(QDropEvent *event);

	// SLOT:
	private slots:
	void on_pushButton_PeAnalysis_clicked();
	void on_treeWidget_ImportInfo_itemClicked(QTreeWidgetItem *item, int column);     // click ImportInfo item
	void on_treeWidget_Process_itemClicked(QTreeWidgetItem *item, int column);

	void on_tabWidget_currentChanged(int index);

	void on_pushButton_Clear_clicked();

    void on_radioButton_4_clicked();        // Clear File's Way
    void on_radioButton_3_clicked();
    void on_radioButton_2_clicked();







// PE:

private:
	TCHAR* m_PePath;
	LPBYTE m_p;
	PIMAGE_NT_HEADERS      m_pNt;
	PIMAGE_FILE_HEADER     m_pFile;
	PIMAGE_OPTIONAL_HEADER m_pOptionHeader;

	DWORD RvaToOffset(DWORD rva);
	DWORD FoaToRva(DWORD foa);
	DWORD VaToOffset(DWORD Va);

	bool IsPeFile();
	bool PaserPeBaseInfo();
	void PaserDatadirectory();
	void PaserSectionInfo();
	void PaserExportInfo();
	void PaserImportInfo();
	void PaserImportAPIInfo(DWORD OriginalFirstThunk);        // Actually Original FirstThunk and FirstThunk are the same!
	void PaserResourceInfo();





// File:
private:
	bool DelDir(const QString & path);
	QFileInfoList GetFileList(QString path);

	QStringList m_CustomTrashSuffix;
	QStringList m_CustomTrashPath;
	QString     m_TrashiPathInLineEdit;
	QString     m_VirusPath;

	int m_delWay = 0;




// service and window
private:
	void TraverseService();

	
	
	
// Process:
private:
	void TraverseProcess();
	bool KillProcess(DWORD dwProcessID);
	void TraverseThread(DWORD dwPid);
	bool SuspendThread(DWORD dwThreadID);
	void TraverseModule(DWORD dwPid);

	QMenu* ProcessMenu = new QMenu(this);




private:
	Ui::Why *ui;

	

};

#endif // WHY_H
