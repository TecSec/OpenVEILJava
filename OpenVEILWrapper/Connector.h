//	Copyright (c) 2015, TecSec, Inc.
//
//	Redistribution and use in source and binary forms, with or without
//	modification, are permitted provided that the following conditions are met:
//	
//		* Redistributions of source code must retain the above copyright
//		  notice, this list of conditions and the following disclaimer.
//		* Redistributions in binary form must reproduce the above copyright
//		  notice, this list of conditions and the following disclaimer in the
//		  documentation and/or other materials provided with the distribution.
//		* Neither the name of TecSec nor the names of the contributors may be
//		  used to endorse or promote products derived from this software 
//		  without specific prior written permission.
//		 
//	ALTERNATIVELY, provided that this notice is retained in full, this product
//	may be distributed under the terms of the GNU General Public License (GPL),
//	in which case the provisions of the GPL apply INSTEAD OF those given above.
//		 
//	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
//	ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
//	WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
//	DISCLAIMED.  IN NO EVENT SHALL TECSEC BE LIABLE FOR ANY 
//	DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
//	(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
//	LOSS OF USE, DATA OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
//	ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
//	(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
//	SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
#pragma once
#include <jni.h>
#include "com_tecsec_OpenVEIL_Connector.h"
#include "com_tecsec_OpenVEIL_GenericConnector.h"
#include "com_tecsec_OpenVEIL_KeyVEILConnector.h"
#include "OpenVEIL.h"
#include "handle.h"
#include "Token.h"
#include "Favorite.h"

class Connector
{
public:
	Connector();
	virtual ~Connector();
	virtual ConnectionStatus connectToServer(const tsAscii& url, const tsAscii& username, const tsAscii& password) = 0;
	virtual void disconnect();
	virtual bool isConnected();
	virtual bool sendJsonRequest(const tsAscii& verb, const tsAscii& cmd, const tsAscii& inData, tsAscii& outData, int& status);
	virtual bool sendBase64Request(const tsAscii& verb, const tsAscii& cmd, const tsAscii& inData, tsAscii& outData, int& status);
	virtual bool sendRequest(const tsAscii& verb, const tsAscii& cmd, const tsData& inData, tsData& outData, int& status);
protected:
	std::shared_ptr<IKeyVEILConnector> conn;

	bool isReady();
};

class GenericConnector : public Connector
{
public:
	GenericConnector();
	virtual ~GenericConnector();
	virtual ConnectionStatus connectToServer(const tsAscii& url, const tsAscii& username, const tsAscii& password);
};

class KeyVEILConnector : public Connector
{
public:
	KeyVEILConnector();
	virtual ~KeyVEILConnector();
	virtual ConnectionStatus connectToServer(const tsAscii& url, const tsAscii& username, const tsAscii& password);

	bool refresh();
	size_t tokenCount();
	Token* tokenByIndex(size_t index);
	Token* tokenByName(const tsAscii& tokenName);
	Token* tokenBySerialNumber(const tsData& serialNumber);
	Token* tokenById(const tsAscii& id);

	size_t favoriteCount();
	Favorite* favoriteByIndex(size_t index);
	Favorite* favoriteByName(const tsAscii& name);
	Favorite* favoriteById(const tsAscii& id);
	tsAscii createFavorite(Token* token, const tsData& headerData, const tsAscii& name);
	tsAscii createFavorite(const tsAscii& tokenId, const tsData& headerData, const tsAscii& name);
	tsAscii createFavorite(const tsData& tokenSerial, const tsData& headerData, const tsAscii& name);
	bool DeleteFavorite(const tsAscii& id);
	bool UpdateFavoriteName(const tsAscii& id, const tsAscii& name);
	bool UpdateFavorite(const tsAscii& id, const tsData& setTo);
	size_t tokenCountForEnterpriseId(const tsAscii& enterpriseId);
	Token* tokenForEnterprise(const tsAscii& enterpriseId, size_t index);
	size_t favoriteCountForEnterprise(const tsAscii& enterpriseId);
	Favorite* favoriteForEnterprise(const tsAscii& enterpriseId, size_t index);

};

