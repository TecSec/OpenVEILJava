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
#include "com_tecsec_OpenVEIL_Session.h"
#include "OpenVEIL.h"
#include "handle.h"
#include "Favorite.h"
#include "CmsHeader.h"
#include "FileVEILSupport.h"

// Used in the file encrypt and decrypt routines
class StatusClass : public IFileVEILOperationStatus, public tsmod::IObject
{
public:
	StatusClass() {}
	virtual bool Status(const tsAscii& taskName, int taskNumber, int ofTaskCount, int taskPercentageDone)
	{
		//if (g_doStatus)
		//{
		//	ts_out << "Task " << taskNumber << " of " << ofTaskCount << " " << taskName << " " << taskPercentageDone << "%" << endl;
		//}
		return true;
	}
	virtual void    FailureReason(const tsAscii&failureText)
	{
		//ERROR(failureText);
	}

private:
	virtual ~StatusClass() {}
};

class Session
{
public:
	Session();
	Session(std::shared_ptr<IKeyVEILSession> _sess);
	~Session();
	void release();
	void close();
	LoginStatus login(const tsAscii& pin);
	bool isLoggedIn();
	bool logout();
	//bool GenerateWorkingKey(Asn1::CTS::CkmCombineParameters& params, std::function<bool(Asn1::CTS::CkmCombineParameters&, tsData&)> headerCallback, tsData &WorkingKey);
	//bool RegenerateWorkingKey(Asn1::CTS::CkmCombineParameters& params, tsData &WorkingKey);
	tsAscii getProfile();
	bool isLocked();
	size_t retriesLeft();
	bool isValid();
	Session* duplicate();
	bool encryptFileUsingFavorite(Favorite* fav, const tsAscii& sourceFile, bool compress, const tsAscii& encryptedFile);
	bool decryptFile(const tsAscii& encryptedFile, const tsAscii& decryptedFile);
	tsData encryptDataUsingFavorite(Favorite* fav, const tsData& sourceData, bool compress);
	tsData decryptData(const tsData& encryptedData);

	std::shared_ptr<IKeyVEILSession> handle() { return _dataHolder; }
protected:
	std::shared_ptr<IKeyVEILSession> _dataHolder;

	bool isReady()
	{
		return !!_dataHolder;
	}
};
