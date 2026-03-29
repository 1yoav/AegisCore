#include "NetworkMonitor.h"

void NetworkMonitor::startNetworkScan()
{
	INetFwRule* pFwRule = NULL;
	INetFwPolicy2* pNetFwPolicy2 = NULL;

	// Block specific IP ranges or ports (3333, 4444, 9999)
	//pFwRule->put_RemoteAddresses(L"192.168.1.100"); // mining pool IP
	//pFwRule->put_Action(NET_FW_ACTION_BLOCK);
	//pNetFwPolicy2->Rules->Add(pFwRule);

}
