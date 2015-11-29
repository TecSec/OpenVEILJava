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
#include <jni.h>
#include "Favorite.h"
#include "OpenVEIL.h"
#include "handle.h"
#include "Session.h"

Favorite::Favorite()
{

}
Favorite::Favorite(std::shared_ptr<IFavorite> _fav) : _dataHolder(_fav)
{

}
Favorite::~Favorite()
{
	release();
}
void Favorite::release()
{
	_dataHolder.reset();
}
tsAscii Favorite::getFavoriteId()
{
	if (!isReady())
		return "";
	return ToString()(handle()->favoriteId()).c_str();
}
void Favorite::setFavoriteId(const tsAscii& setTo)
{
	if (!isReady())
		return;
	handle()->favoriteId(ToGuid()(setTo.c_str()));
}
tsAscii Favorite::getEnterpriseId()
{
	if (!isReady())
		return "";
	return ToString()(handle()->enterpriseId()).c_str();
}
void Favorite::setEnterpriseId(const tsAscii& setTo)
{
	if (!isReady())
		return;
	handle()->enterpriseId(ToGuid()(setTo.c_str()));
}
tsAscii Favorite::getFavoriteName()
{
	if (!isReady())
		return "";
	return handle()->favoriteName().c_str();
}
void Favorite::setFavoriteName(const tsAscii& setTo)
{
	if (!isReady())
		return;
	handle()->favoriteName(setTo.c_str());
}
tsData Favorite::getTokenSerialNumber()
{
	if (!isReady())
		return "";
	return handle()->tokenSerialNumber();
}
void Favorite::setTokenSerialNumber(const tsData& setTo)
{
	if (!isReady())
		return;
	handle()->tokenSerialNumber(setTo);
}
tsData Favorite::headerData()
{
	if (!isReady())
		return tsData();
	return handle()->headerData();
}
void Favorite::headerData(const tsData& setTo)
{
	if (!isReady())
		return;
	handle()->headerData(setTo);
}
bool Favorite::encryptFile(Session* session, const tsAscii& sourceFile, bool compress, const tsAscii& encryptedFile)
{
	std::shared_ptr<IFileVEILOperations> fileOps;
	std::shared_ptr<ICmsHeader> header;
	std::shared_ptr<IFileVEILOperationStatus> status;
	tsAscii inputFile(sourceFile.c_str());
	tsAscii outputFile(encryptedFile.c_str());

	if (!isReady())
		return false;

	if (!InitializeCmsHeader())
		return false;

	if (xp_GetFileAttributes(inputFile) == XP_INVALID_FILE_ATTRIBUTES || xp_IsDirectory(inputFile))
	{
		throw tsAscii() << "File -> " << encryptedFile << " <- does not exist Decrypt operation aborted";
	}

	status = ::ServiceLocator()->Finish<IFileVEILOperationStatus>(new StatusClass());

	if (!(fileOps = CreateFileVEILOperationsObject()) ||
		!(fileOps->SetStatusInterface(status)) ||
		!(fileOps->SetSession(session->handle())))
	{
		throw tsAscii("An error occurred while building the file decryptor.  The " VEILCORENAME " may be damaged.");
	}

	// Create output file name based on the input file name
	if (outputFile.size() == 0)
	{
		outputFile = inputFile;
		outputFile += ".ckm";
	}
	if (!(header = ::ServiceLocator()->get_instance<ICmsHeader>("/CmsHeader")) || !header->FromBytes(handle()->headerData()))
	{
		throw tsAscii("An error occurred while building the encryption header.");
	}

	// Indicate compression is desired.
	if (compress)
	{
		header->SetCompressionType(ct_zLib);
	}
	else
	{
		header->SetCompressionType(ct_None);
	}
	if (header->GetEncryptionAlgorithmID() == TS_ALG_INVALID)
		header->SetEncryptionAlgorithmID(TS_ALG_AES_GCM_256);

	if (!(fileOps->EncryptFileAndStreams(inputFile.c_str(), outputFile.c_str(), header, compress ? ct_zLib : ct_None,
		header->GetEncryptionAlgorithmID(), OIDtoID(header->GetDataHashOID().ToOIDString().c_str()),
		header->HasHeaderSigningPublicKey(), true,
		(Alg2Mode(header->GetEncryptionAlgorithmID()) == CKM_SymMode_GCM ||
			Alg2Mode(header->GetEncryptionAlgorithmID()) == CKM_SymMode_CCM) ?
		TS_FORMAT_CMS_ENC_AUTH : TS_FORMAT_CMS_CT_HASHED,
		false, header->GetPaddingType(), 5000000)))
	{
		//if (!connector->isConnected())
		//{
		//	WARN("The connection to the server was lost.");
		//}
		//return 303;
		throw tsAscii("Encryption failed.");
	}

	return true;
}
tsData Favorite::encryptData(Session* session, const tsData& sourceData, bool compress)
{
	if (!isReady())
		return tsData();

	tsData encData;

	if (sourceData.size() == 0)
	{
		return tsData();
	}

	if (!InitializeCmsHeader())
		return tsData();

	std::shared_ptr<IFileVEILOperations> fileOps;
	std::shared_ptr<IFileVEILOperationStatus> status;
	std::shared_ptr<ICmsHeader> header;

	if (!session->handle())
	{
		throw tsAscii("Session not valid.");
	}

	status = ::ServiceLocator()->Finish<IFileVEILOperationStatus>(new StatusClass());

	if (!(fileOps = CreateFileVEILOperationsObject()) ||
		!(fileOps->SetStatusInterface(status)) ||
		!(fileOps->SetSession(session->handle())))
	{
		throw tsAscii("An error occurred while building the file encryptor.  The " VEILCORENAME " may be damaged.");
	}
	if (!(header = ::ServiceLocator()->get_instance<ICmsHeader>("/CmsHeader")) || !header->FromBytes(handle()->headerData()))
	{
		throw tsAscii("An error occurred while building the encryption header.");
	}

	if (!header)
	{
		throw tsAscii("An error occurred while building the encryption header.");
	}

	// Indicate compression is desired.
	if (compress)
	{
		header->SetCompressionType(ct_zLib);
	}
	else
	{
		header->SetCompressionType(ct_None);
	}
	if (header->GetEncryptionAlgorithmID() == TS_ALG_INVALID)
		header->SetEncryptionAlgorithmID(TS_ALG_AES_GCM_256);

	if (!(fileOps->EncryptCryptoData(sourceData, encData, header, compress ? ct_zLib : ct_None,
		header->GetEncryptionAlgorithmID(), OIDtoID(header->GetDataHashOID().ToOIDString().c_str()),
		header->HasHeaderSigningPublicKey(), true,
		(Alg2Mode(header->GetEncryptionAlgorithmID()) == CKM_SymMode_GCM ||
			Alg2Mode(header->GetEncryptionAlgorithmID()) == CKM_SymMode_CCM) ?
		TS_FORMAT_CMS_ENC_AUTH : TS_FORMAT_CMS_CT_HASHED,
		false, header->GetPaddingType(), 5000000)))
	{
		//if (!connector->isConnected())
		//{
		//	//WARN("The connection to the server was lost.");
		//	return 304;
		//}

		//cout << "  Something went wrong on encryption. " << endl;
		//return 305;
		throw tsAscii("Encryption failed.");
	}

	return encData;
}



/*
* Class:     com_tecsec_OpenVEIL_Favorite
* Method:    release
* Signature: ()V
*/
JNIEXPORT void JNICALL Java_com_tecsec_OpenVEIL_Favorite_release(JNIEnv *env, jobject thisObj)
{
	// Get a reference to this object's class
	jclass thisClass = env->GetObjectClass(thisObj);

	Favorite* This = getHandle<Favorite>(env, thisObj);

	if (This == nullptr)
		return;
	This->release();
}

/*
* Class:     com_tecsec_OpenVEIL_Favorite
* Method:    getFavoriteId
* Signature: ()Ljava/lang/String;
*/
JNIEXPORT jstring JNICALL Java_com_tecsec_OpenVEIL_Favorite_getFavoriteId(JNIEnv *env, jobject thisObj)
{
	// Get a reference to this object's class
	jclass thisClass = env->GetObjectClass(thisObj);

	Favorite* This = getHandle<Favorite>(env, thisObj);

	if (This == nullptr)
		return tsAsciiToJstring(env, "");
	return tsAsciiToJstring(env, This->getFavoriteId());
}

/*
* Class:     com_tecsec_OpenVEIL_Favorite
* Method:    setFavoriteId
* Signature: (Ljava/lang/String;)V
*/
JNIEXPORT void JNICALL Java_com_tecsec_OpenVEIL_Favorite_setFavoriteId(JNIEnv *env, jobject thisObj, jstring value)
{
	// Get a reference to this object's class
	jclass thisClass = env->GetObjectClass(thisObj);

	Favorite* This = getHandle<Favorite>(env, thisObj);

	if (This == nullptr)
		return;
	This->setFavoriteId(jstringToTsAscii(env, value));
}

/*
* Class:     com_tecsec_OpenVEIL_Favorite
* Method:    getEnterpriseId
* Signature: ()Ljava/lang/String;
*/
JNIEXPORT jstring JNICALL Java_com_tecsec_OpenVEIL_Favorite_getEnterpriseId(JNIEnv *env, jobject thisObj)
{
	// Get a reference to this object's class
	jclass thisClass = env->GetObjectClass(thisObj);

	Favorite* This = getHandle<Favorite>(env, thisObj);

	if (This == nullptr)
		return tsAsciiToJstring(env, "");
	return tsAsciiToJstring(env, This->getEnterpriseId());
}

/*
* Class:     com_tecsec_OpenVEIL_Favorite
* Method:    setEnterpriseId
* Signature: (Ljava/lang/String;)V
*/
JNIEXPORT void JNICALL Java_com_tecsec_OpenVEIL_Favorite_setEnterpriseId(JNIEnv *env, jobject thisObj, jstring value)
{
	// Get a reference to this object's class
	jclass thisClass = env->GetObjectClass(thisObj);

	Favorite* This = getHandle<Favorite>(env, thisObj);

	if (This == nullptr)
		return;
	This->setEnterpriseId(jstringToTsAscii(env, value));
}

/*
* Class:     com_tecsec_OpenVEIL_Favorite
* Method:    getFavoriteName
* Signature: ()Ljava/lang/String;
*/
JNIEXPORT jstring JNICALL Java_com_tecsec_OpenVEIL_Favorite_getFavoriteName(JNIEnv *env, jobject thisObj)
{
	// Get a reference to this object's class
	jclass thisClass = env->GetObjectClass(thisObj);

	Favorite* This = getHandle<Favorite>(env, thisObj);

	if (This == nullptr)
		return tsAsciiToJstring(env, "");
	return tsAsciiToJstring(env, This->getFavoriteName());
}

/*
* Class:     com_tecsec_OpenVEIL_Favorite
* Method:    setFavoriteName
* Signature: (Ljava/lang/String;)V
*/
JNIEXPORT void JNICALL Java_com_tecsec_OpenVEIL_Favorite_setFavoriteName(JNIEnv *env, jobject thisObj, jstring value)
{
	// Get a reference to this object's class
	jclass thisClass = env->GetObjectClass(thisObj);

	Favorite* This = getHandle<Favorite>(env, thisObj);

	if (This == nullptr)
		return;
	This->setFavoriteName(jstringToTsAscii(env, value));
}

/*
* Class:     com_tecsec_OpenVEIL_Favorite
* Method:    getTokenSerialNumber
* Signature: ()Ljava/lang/String;
*/
JNIEXPORT jbyteArray JNICALL Java_com_tecsec_OpenVEIL_Favorite_getTokenSerialNumber(JNIEnv *env, jobject thisObj)
{
	// Get a reference to this object's class
	jclass thisClass = env->GetObjectClass(thisObj);

	Favorite* This = getHandle<Favorite>(env, thisObj);

	if (This == nullptr)
		return nullptr;
	return tsDataToJbyteArray(env, This->getTokenSerialNumber());
}

/*
* Class:     com_tecsec_OpenVEIL_Favorite
* Method:    setTokenSerialNumber
* Signature: (Ljava/lang/String;)V
*/
JNIEXPORT void JNICALL Java_com_tecsec_OpenVEIL_Favorite_setTokenSerialNumber(JNIEnv *env, jobject thisObj, jbyteArray value)
{
	// Get a reference to this object's class
	jclass thisClass = env->GetObjectClass(thisObj);

	Favorite* This = getHandle<Favorite>(env, thisObj);

	if (This == nullptr)
		return;
	This->setTokenSerialNumber(jbyteArrayToTsData(env, value));
}

/*
* Class:     com_tecsec_OpenVEIL_Favorite
* Method:    getHheaderData
* Signature: ()[B
*/
JNIEXPORT jbyteArray JNICALL Java_com_tecsec_OpenVEIL_Favorite_getHeaderData(JNIEnv *env, jobject thisObj)
{
	// Get a reference to this object's class
	jclass thisClass = env->GetObjectClass(thisObj);

	Favorite* This = getHandle<Favorite>(env, thisObj);

	if (This == nullptr)
		return nullptr;
	return tsDataToJbyteArray(env, This->headerData());
}

/*
* Class:     com_tecsec_OpenVEIL_Favorite
* Method:    setHeaderData
* Signature: ([B)V
*/
JNIEXPORT void JNICALL Java_com_tecsec_OpenVEIL_Favorite_setHeaderData(JNIEnv *env, jobject thisObj, jbyteArray value)
{
	// Get a reference to this object's class
	jclass thisClass = env->GetObjectClass(thisObj);

	Favorite* This = getHandle<Favorite>(env, thisObj);

	if (This == nullptr)
		return;
	This->headerData(jbyteArrayToTsData(env, value));
}

/*
* Class:     com_tecsec_OpenVEIL_Favorite
* Method:    encryptFile
* Signature: (Lcom/tecsec/OpenVEIL/Session;Ljava/lang/String;ZLjava/lang/String;)Z
*/
JNIEXPORT jboolean JNICALL Java_com_tecsec_OpenVEIL_Favorite_encryptFile(JNIEnv *env, jobject thisObj, jobject session, jstring sourceFile, jboolean compress, jstring destFile)
{
	// Get a reference to this object's class
	jclass thisClass = env->GetObjectClass(thisObj);

	Favorite* This = getHandle<Favorite>(env, thisObj);
	Session* mySession = getHandle<Session>(env, session);

	if (This == nullptr)
		return JNI_FALSE;

	try
	{
		return This->encryptFile(mySession, jstringToTsAscii(env, sourceFile), compress, jstringToTsAscii(env, destFile));
	}
	catch (tsAscii &ex)
	{
		THROW_JAVA_EXCEPTION(ex.c_str());
		return JNI_FALSE;
	}
}

/*
* Class:     com_tecsec_OpenVEIL_Favorite
* Method:    encryptData
* Signature: (Lcom/tecsec/OpenVEIL/Session;[BZ)[B
*/
JNIEXPORT jbyteArray JNICALL Java_com_tecsec_OpenVEIL_Favorite_encryptData(JNIEnv *env, jobject thisObj, jobject session, jbyteArray sourceData, jboolean compress)
{
	// Get a reference to this object's class
	jclass thisClass = env->GetObjectClass(thisObj);

	Favorite* This = getHandle<Favorite>(env, thisObj);
	Session* mySession = getHandle<Session>(env, session);

	if (This == nullptr)
		return JNI_FALSE;

	try
	{
		return tsDataToJbyteArray(env, This->encryptData(mySession, jbyteArrayToTsData(env, sourceData), compress));
	}
	catch (tsAscii &ex)
	{
		THROW_JAVA_EXCEPTION(ex.c_str());
		return nullptr;
	}
}

/*
* Class:     com_tecsec_OpenVEIL_Favorite
* Method:    initialize
* Signature: ()V
*/
JNIEXPORT void JNICALL Java_com_tecsec_OpenVEIL_Favorite_initialize(JNIEnv *env, jobject thisObj)
{
	setHandle(env, thisObj, new Favorite());
}

/*
* Class:     com_tecsec_OpenVEIL_Favorite
* Method:    terminate
* Signature: ()V
*/
JNIEXPORT void JNICALL Java_com_tecsec_OpenVEIL_Favorite_terminate(JNIEnv *env, jobject thisObj)
{
	Favorite* This = getHandle<Favorite>(env, thisObj);

	if (This != nullptr)
	{
		delete This;
		This = nullptr;
		setHandle(env, thisObj, This);
	}
}

