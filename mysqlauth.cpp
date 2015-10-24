/*
 * Copyright (C) 2004-2015 ZNC, see the NOTICE file for details.
 * Copyright (C) 2008 Heiko Hund <heiko@ist.eigentlich.net>
 * Copyright (C) 2015 Daniel Sonck <daniel@sonck.nl>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * @class CMysqlAuthMod
 * @author Daniel Sonck <daniel@sonck.nl>
 * @brief MySQL authentication module for znc.
 */

#include <znc/znc.h>
#include <znc/User.h>
#include <znc/IRCNetwork.h>

#include "mysql_connection.h"
#include "mysql_driver.h"

#include <cppconn/driver.h>
#include <cppconn/exception.h>
#include <cppconn/resultset.h>
#include <cppconn/statement.h>


#include <memory.h>

class CMysqlAuthMod : public CModule {
public:
	MODCONSTRUCTOR(CMysqlAuthMod) {
		m_Cache.SetTTL(60000/*ms*/);
		
		m_sHost = "localhost";
		m_sUser = "znc";
		m_sPass = "zncpass";
		m_sDB   = "znc";


		AddHelpCommand();
		AddCommand("CreateUser",       static_cast<CModCommand::ModCmdFunc>(&CMysqlAuthMod::CreateUserCommand),
			"[yes|no]");
		AddCommand("DenyLoadMod",      static_cast<CModCommand::ModCmdFunc>(&CMysqlAuthMod::DenyLoadModCommand),
			"[yes|no]");
		AddCommand("CloneUser",        static_cast<CModCommand::ModCmdFunc>(&CMysqlAuthMod::CloneUserCommand),
			"[username]");
		AddCommand("DisableCloneUser", static_cast<CModCommand::ModCmdFunc>(&CMysqlAuthMod::DisableCloneUserCommand));
		AddCommand("SetQuery",  static_cast<CModCommand::ModCmdFunc>(&CMysqlAuthMod::SetQueryCommand),
			"[query]");
		AddCommand("GetQuery",  static_cast<CModCommand::ModCmdFunc>(&CMysqlAuthMod::GetQueryCommand));

		AddCommand("LoadUserMods", static_cast<CModCommand::ModCmdFunc>(&CMysqlAuthMod::LoadUserModsCommand),"[mods]");
		AddCommand("LoadNetworkMods", static_cast<CModCommand::ModCmdFunc>(&CMysqlAuthMod::LoadNetworkModsCommand),"[mods]");
		AddCommand("UserMods", static_cast<CModCommand::ModCmdFunc>(&CMysqlAuthMod::UserModsCommand));

		AddCommand("AutoClearChanBuffer", static_cast<CModCommand::ModCmdFunc>(&CMysqlAuthMod::AutoClearChanBufferCommand),"[yes|no]");
	
		AddCommand("SetNetworks", static_cast<CModCommand::ModCmdFunc>(&CMysqlAuthMod::SetNetworksCommand), "[net \"serv\" ...] | ...");
		AddCommand("Networks", static_cast<CModCommand::ModCmdFunc>(&CMysqlAuthMod::NetworksCommand));
	}

	virtual ~CMysqlAuthMod() {
	}

	void OnModCommand(const CString& sCommand) override {
		if (GetUser()->IsAdmin()) {
			HandleCommand(sCommand);
		} else {
			PutModule("Access denied");
		}
	}

	bool OnLoad(const CString& sArgs, CString& sMessage) override {
		VCString vsArgs;
		VCString::const_iterator it;
		sArgs.Split(" ", vsArgs, false);

		if(vsArgs.size() > 0)
			SetNV("MysqlHost",vsArgs.at(0));
		if(vsArgs.size() > 1)
			SetNV("MysqlUser",vsArgs.at(1));
		if(vsArgs.size() > 2)
			SetNV("MysqlPass",vsArgs.at(2));
		if(vsArgs.size() > 3)
			SetNV("MysqlDB",vsArgs.at(3));
		
		SetArgs("");

		m_sHost = GetNV("MysqlHost");
		m_sUser = GetNV("MysqlUser");
		m_sPass = GetNV("MysqlPass");
		m_sDB  = GetNV("MysqlDB");

		return true;
	}

	EModRet OnLoginAttempt(std::shared_ptr<CAuthBase> Auth) override {
		const CString& sUsername = Auth->GetUsername();
		const CString& sPassword = Auth->GetPassword();
		CUser *pUser(CZNC::Get().FindUser(sUsername));
		bool bSuccess = false;

		if (!pUser && !CreateUser()) {
			return CONTINUE;
		}

		CString sRealname;

		const CString sCacheKey(CString(sUsername + ":" + sPassword).MD5());
		if (m_Cache.HasItem(sCacheKey)) {
			bSuccess = true;
			DEBUG("mysqlauth: Found [" + sUsername + "] in cache");
		} else {

			
			try {
			sql::Driver *driver = get_driver_instance();

			sql::Connection *con = driver->connect(m_sHost,m_sUser,m_sPass);

			con->setSchema(m_sDB);

			sql::Statement *stmt = con->createStatement();
			sql::ResultSet *res  = stmt->executeQuery(GetQuery()
			                                          .Replace_n("$u$",sUsername)
								  .Replace_n("$p$",sPassword));

			while(res->next())
			{
				bSuccess = true;

				sRealname = res->getString("realname").asStdString();
			}

			if(sRealname.empty())
			{
			  sRealname = sUsername;
			}
			
			delete res;
			delete stmt;
			delete con;
		
			} catch (sql::SQLException &e) {
				DEBUG(CString("mysqlauth: SQLException : Err : ")+e.what());
				DEBUG(CString("mysqlauth: Error code: ")+CString(e.getErrorCode()));
				DEBUG(CString("mysqlauth: SQL state: ")+e.getSQLState());
			}

			if(bSuccess)
			{
				m_Cache.AddItem(sCacheKey);

				DEBUG("mysqlauth: Successful MySQL authentication [" + sUsername + "]");

			}

		}

		if (bSuccess) {
			if (!pUser) {
				CString sErr;
				pUser = new CUser(sUsername);

				if (ShouldCloneUser()) {
					CUser *pBaseUser = CZNC::Get().FindUser(CloneUser());

					if (!pBaseUser) {
						DEBUG("mysqlauth: Clone User [" << CloneUser() << "] User not found");
						delete pUser;
						pUser = nullptr;
					}

					if (pUser && !pUser->Clone(*pBaseUser, sErr)) {
						DEBUG("mysqlauth: Clone User [" << CloneUser() << "] failed: " << sErr);
						delete pUser;
						pUser = nullptr;
					}
				}

				if (pUser) {
					CString retVal;
					// "::" is an invalid MD5 hash, so user won't be able to login by usual method
					pUser->SetPass("::", CUser::HASH_MD5, "::");
					pUser->SetNick(sUsername);
					pUser->SetAltNick(sUsername);
					pUser->SetIdent(sUsername);
					pUser->SetRealName(sRealname);
					pUser->SetDenyLoadMod(DenyLoadMod());
					pUser->SetAutoClearChanBuffer(AutoClearChanBuffer());
					
					CModules & mods = pUser->GetModules();
					  
					VCString loadmods;

					LoadUserMods().Split(" ",loadmods, false);

					DEBUG("mysqlauth: UserMods: "+LoadUserMods());

					for(CString loadmod : loadmods) {
					    DEBUG("mysqlauth: Loading: "+loadmod);
					    mods.LoadModule(loadmod,"",CModInfo::UserModule,pUser,nullptr,retVal);
					    DEBUG(retVal);
					}

					loadmods.clear();

					// Create correct network
					CString err;

					VCString nets;
					Networks().Split("|",nets,false,"","",true,true);

					for(CString neta : nets)
					{

						CIRCNetwork *net = pUser->AddNetwork(neta.Token(0),err);

						if(net)
						{
						  VCString servs;
						  neta.Token(1,true).Split(" ",servs,false,"\"","\"");

						  for(CString serv : servs) {
						  	net->AddServer(serv);
						  }

						  CModules & netmods = net->GetModules();
					
						  netmods.LoadModule("nickserv",sPassword,CModInfo::NetworkModule,pUser,net,retVal);

						  LoadNetworkMods().Split(" ", loadmods, false);
					  
						  DEBUG("mysqlauth: NetworkMods: "+LoadNetworkMods());

						  for(CString loadmod : loadmods) {
						    DEBUG("mysqlauth: Loading: "+loadmod);
						    netmods.LoadModule(loadmod,"",CModInfo::NetworkModule,pUser,net,retVal);
						    DEBUG(retVal);
						  }
						}
					}
				}

				if (pUser && !CZNC::Get().AddUser(pUser, sErr)) {
					DEBUG("mysqlauth: Add user [" << sUsername << "] failed: " << sErr);
					delete pUser;
					pUser = nullptr;
				}
			}

			if (pUser) {
				Auth->AcceptLogin(*pUser);
				return HALT;
			}
		}

		return CONTINUE;
	}

	void CreateUserCommand(const CString &sLine) {
		CString sCreate = sLine.Token(1);

		if (!sCreate.empty()) {
			SetNV("CreateUser", sCreate);
		}

		if (CreateUser()) {
			PutModule("We will create users on their first login");
		} else {
			PutModule("We will not create users on their first login");
		}
	}

	void DenyLoadModCommand(const CString &sLine) {
		CString sDenyLoadMod = sLine.Token(1);

		if(!sDenyLoadMod.empty()) {
			SetNV("DenyLoadMod", sDenyLoadMod);
		}

		if(DenyLoadMod()) {
			PutModule("New users won't be able to LoadMod");
		} else {
			PutModule("New users will be able to LoadMod");
		}
	}

	void AutoClearChanBufferCommand(const CString &sLine) {
		CString sAutoClearChanBuffer = sLine.Token(1);

		if(!sAutoClearChanBuffer.empty()) {
			SetNV("AutoClearChanBuffer", sAutoClearChanBuffer);
		}

		if(AutoClearChanBuffer()) {
			PutModule("New users will auto-clear channel buffers");
		} else {
			PutModule("New users will not auto-clear channel buffers");
		}
	}

	void SetQueryCommand(const CString &sLine) {
		CString sQuery = sLine.Token(1,true);

		if (!sQuery.empty()) {
			SetNV("Query", sQuery);
		}

		PutModule("Succesfully updated query to: "+sQuery);
	}

	void GetQueryCommand(const CString &sLine) {
		PutModule("Query currently set to: "+GetNV("Query"));
	}

	void CloneUserCommand(const CString &sLine) {
		CString sUsername = sLine.Token(1);

		if (!sUsername.empty()) {
			SetNV("CloneUser", sUsername);
		}

		if (ShouldCloneUser()) {
			PutModule("We will clone [" + CloneUser() + "]");
		} else {
			PutModule("We will not clone a user");
		}
	}

	void LoadUserModsCommand(const CString &sLine) {
		CString sMods = sLine.Token(1,true);

		if(!sMods.empty()) {
			SetNV("LoadUserMods", sMods);
		}

		PutModule("UserMods to autoload: "+ sMods);
	}

	void LoadNetworkModsCommand(const CString &sLine) {
		CString sMods = sLine.Token(1,true);

		if(!sMods.empty()) {
			SetNV("LoadNetworkMods", sMods);
		}

		PutModule("NetworkMods to autoload: " + sMods);
	}

	void SetNetworksCommand(const CString &sLine) {
		CString sNets = sLine.Token(1,true);

		if(!sNets.empty()) {
			SetNV("Networks", sNets);
		}

		PutModule("Networks to add: " + Networks());
	}

	void NetworksCommand(const CString &sLine) {
		PutModule("Networks to add: " + Networks());
	}

	void UserModsCommand(const CString &sList) {
		PutModule("UserMods to autoload: " + LoadUserMods());
		PutModule("NetworkMods to autoload: " + LoadNetworkMods());
	}

	void DisableCloneUserCommand(const CString &sLine) {
		DelNV("CloneUser");
		PutModule("Clone user disabled");
	}

	bool CreateUser() const {
		return GetNV("CreateUser").ToBool();
	}

	bool DenyLoadMod() const {
		return GetNV("DenyLoadMod").ToBool();
	}

	bool AutoClearChanBuffer() const {
		return GetNV("AutoClearChanBuffer").ToBool();
	}

	CString CloneUser() const {
		return GetNV("CloneUser");
	}

	bool ShouldCloneUser() {
		return !GetNV("CloneUser").empty();
	}

	CString GetQuery() const {
		return GetNV("Query");
	}

	CString LoadUserMods() const {
		return GetNV("LoadUserMods");
	}

	CString LoadNetworkMods() const {
		return GetNV("LoadNetworkMods");
	}

	CString Networks() const {
		return GetNV("Networks");
	}

protected:
	TCacheMap<CString>     m_Cache;

	CString m_sHost;
	CString m_sUser;
	CString m_sPass;
	CString m_sDB;

};

template<> void TModInfo<CMysqlAuthMod>(CModInfo& Info) {
//	Info.SetWikiPage("cyrusauth");
	Info.SetHasArgs(true);
	Info.SetArgsHelpText("This global module takes up 4 arguments: [host] [user] [pass] [db]");
}

GLOBALMODULEDEFS(CMysqlAuthMod, "Allow users to authenticate via MySQL password verification method")
