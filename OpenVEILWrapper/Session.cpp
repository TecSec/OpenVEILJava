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
#include "Session.h"
#include "OpenVEIL.h"
#include "handle.h"

Session::Session()
{

}
Session::Session(std::shared_ptr<IKeyVEILSession> _sess) : _dataHolder(_sess)
{

}
Session::~Session()
{
	release();
}
void Session::release()
{
	_dataHolder.reset();
}
void Session::close()
{
	if (isReady())
	{
		handle()->Close();
	}
}
LoginStatus Session::login(const tsAscii& pin)
{
	if (!isReady())
		return loginStatus_NoServer;
	return handle()->Login(pin.c_str());
}
bool Session::isLoggedIn()
{
	if (!isReady())
		return false;
	return handle()->IsLoggedIn();
}
bool Session::logout()
{
	if (!isReady())
		return false;
	return handle()->Logout();
}
//bool GenerateWorkingKey(Asn1::CTS::CkmCombineParameters& params, std::function<bool(Asn1::CTS::CkmCombineParameters&, tsData&)> headerCallback, tsData &WorkingKey);
//bool RegenerateWorkingKey(Asn1::CTS::CkmCombineParameters& params, tsData &WorkingKey);
tsAscii Session::getProfile()
{
	if (!isReady())
		return "";

	return handle()->GetProfile()->toJSON().ToString();
}
bool Session::isLocked()
{
	if (!isReady())
		return false;
	return handle()->IsLocked();
}
size_t Session::retriesLeft()
{
	if (!isReady())
		return 0;
	return handle()->retriesLeft();
}
bool Session::isValid()
{
	if (!isReady())
	{
		return false;
	}
	return handle()->IsValid();
}
Session* Session::duplicate()
{
	if (!isReady())
		return nullptr;
	return new Session(handle()->Duplicate());
}
bool Session::encryptFileUsingFavorite(Favorite* fav, const tsAscii& sourceFile, bool compress, const tsAscii& encryptedFile)
{
	return fav->encryptFile(this, sourceFile, compress, encryptedFile);
}
bool Session::decryptFile(const tsAscii& encryptedFile, const tsAscii& decryptedFile)
{
	if (!isReady())
		return false;

	if (!InitializeCmsHeader())
		return false;

	std::shared_ptr<IFileVEILOperations> fileOps;
	std::shared_ptr<IFileVEILOperationStatus> status;

	if (xp_GetFileAttributes(encryptedFile) == XP_INVALID_FILE_ATTRIBUTES || xp_IsDirectory(encryptedFile))
	{
		throw tsAscii() << "File -> " << encryptedFile << " <- does not exist Decrypt operation aborted";
	}

	status = ::ServiceLocator()->Finish<IFileVEILOperationStatus>(new StatusClass());

	if (!(fileOps = CreateFileVEILOperationsObject()) ||
		!(fileOps->SetStatusInterface(status)) ||
		!(fileOps->SetSession(handle())))
	{
		throw tsAscii("An error occurred while building the file decryptor.  The " VEILCORENAME " may be damaged.");
	}

	if (!fileOps->DecryptFileAndStreams(encryptedFile, decryptedFile))
	{
		throw tsAscii("Decrypt failed.");
	}

	return true;
}
tsData Session::encryptDataUsingFavorite(Favorite* fav, const tsData& sourceData, bool compress)
{
	return fav->encryptData(this, sourceData, compress);
}
tsData Session::decryptData(const tsData& encryptedData)
{
	if (!isReady())
		return tsData();

	if (!InitializeCmsHeader())
		return tsData();

	std::shared_ptr<IFileVEILOperations> fileOps;
	std::shared_ptr<IFileVEILOperationStatus> status;
	tsData destData;

	status = ::ServiceLocator()->Finish<IFileVEILOperationStatus>(new StatusClass());

	if (!(fileOps = CreateFileVEILOperationsObject()) ||
		!(fileOps->SetStatusInterface(status)) ||
		!(fileOps->SetSession(handle())))
	{
		throw tsAscii("An error occurred while building the file decryptor.  The " VEILCORENAME " may be damaged.");
	}

	if (!fileOps->DecryptCryptoData(encryptedData, destData))
	{
		//if (!connector->isConnected())
		//{
		//	//WARN("The connection to the server was lost.");
		//	return 103;
		//}
		//return 104;
		throw tsAscii("Decrypt failed.");
	}

	//cout << inputData.c_str() << "  successfully decrypted to " << outputData.c_str() << endl;
	return destData;
}


jobject LoginStatusToJava(JNIEnv* env, LoginStatus value)
{
	jclass clSTATUS = env->FindClass("com/tecsec/OpenVEIL/LoginStatus");
	jfieldID fieldId = 0;
	switch (value)
	{
	case loginStatus_BadAuth:
		fieldId = env->GetStaticFieldID(clSTATUS, "BADAUTH", "Lcom/tecsec/OpenVEIL/LoginStatus;");
		break;
	case loginStatus_Connected:
		fieldId = env->GetStaticFieldID(clSTATUS, "CONNECTED", "Lcom/tecsec/OpenVEIL/LoginStatus;");
		break;
	case loginStatus_NoServer:
		fieldId = env->GetStaticFieldID(clSTATUS, "NOSERVER", "Lcom/tecsec/OpenVEIL/LoginStatus;");
		break;
	}
	return env->GetStaticObjectField(clSTATUS, fieldId);
}

/*
* Class:     com_tecsec_OpenVEIL_Session
* Method:    release
* Signature: ()V
*/
JNIEXPORT void JNICALL Java_com_tecsec_OpenVEIL_Session_release
(JNIEnv *env, jobject thisObj)
{
	// Get a reference to this object's class
	jclass thisClass = env->GetObjectClass(thisObj);

	Session* This = getHandle<Session>(env, thisObj);

	if (This == nullptr)
		return;
	This->release();
}

/*
* Class:     com_tecsec_OpenVEIL_Session
* Method:    close
* Signature: ()V
*/
JNIEXPORT void JNICALL Java_com_tecsec_OpenVEIL_Session_close
(JNIEnv *env, jobject thisObj)
{
	// Get a reference to this object's class
	jclass thisClass = env->GetObjectClass(thisObj);

	Session* This = getHandle<Session>(env, thisObj);

	if (This == nullptr)
		return;
	This->close();
}

/*
* Class:     com_tecsec_OpenVEIL_Session
* Method:    login
* Signature: (Ljava/lang/String;)Lcom/tecsec/OpenVEIL/LoginStatus;
*/
JNIEXPORT jobject JNICALL Java_com_tecsec_OpenVEIL_Session_login
(JNIEnv *env, jobject thisObj, jstring password)
{
	// Get a reference to this object's class
	jclass thisClass = env->GetObjectClass(thisObj);

	Session* This = getHandle<Session>(env, thisObj);

	if (This == nullptr)
		return nullptr;
	return LoginStatusToJava(env, This->login(jstringToTsAscii(env, password)));
}

/*
* Class:     com_tecsec_OpenVEIL_Session
* Method:    getIsLoggedIn
* Signature: ()Z
*/
JNIEXPORT jboolean JNICALL Java_com_tecsec_OpenVEIL_Session_getIsLoggedIn
(JNIEnv *env, jobject thisObj)
{
	// Get a reference to this object's class
	jclass thisClass = env->GetObjectClass(thisObj);

	Session* This = getHandle<Session>(env, thisObj);

	if (This == nullptr)
		return JNI_FALSE;
	return This->isLoggedIn() ? JNI_TRUE : JNI_FALSE;
}

/*
* Class:     com_tecsec_OpenVEIL_Session
* Method:    logout
* Signature: ()Z
*/
JNIEXPORT jboolean JNICALL Java_com_tecsec_OpenVEIL_Session_logout
(JNIEnv *env, jobject thisObj)
{
	// Get a reference to this object's class
	jclass thisClass = env->GetObjectClass(thisObj);

	Session* This = getHandle<Session>(env, thisObj);

	if (This == nullptr)
		return JNI_FALSE;
	return This->logout() ? JNI_TRUE : JNI_FALSE;
}

/*
* Class:     com_tecsec_OpenVEIL_Session
* Method:    getProfile
* Signature: ()Ljava/lang/String;
*/
JNIEXPORT jstring JNICALL Java_com_tecsec_OpenVEIL_Session_getProfile
(JNIEnv *env, jobject thisObj)
{
	// Get a reference to this object's class
	jclass thisClass = env->GetObjectClass(thisObj);

	Session* This = getHandle<Session>(env, thisObj);

	if (This == nullptr)
		return nullptr;
	return tsAsciiToJstring(env, This->getProfile());
}

/*
* Class:     com_tecsec_OpenVEIL_Session
* Method:    getIsLocked
* Signature: ()Z
*/
JNIEXPORT jboolean JNICALL Java_com_tecsec_OpenVEIL_Session_getIsLocked
(JNIEnv *env, jobject thisObj)
{
	// Get a reference to this object's class
	jclass thisClass = env->GetObjectClass(thisObj);

	Session* This = getHandle<Session>(env, thisObj);

	if (This == nullptr)
		return JNI_FALSE;
	return This->isLocked() ? JNI_TRUE : JNI_FALSE;
}

/*
* Class:     com_tecsec_OpenVEIL_Session
* Method:    getRetriesLeft
* Signature: ()I
*/
JNIEXPORT jint JNICALL Java_com_tecsec_OpenVEIL_Session_getRetriesLeft
(JNIEnv *env, jobject thisObj)
{
	// Get a reference to this object's class
	jclass thisClass = env->GetObjectClass(thisObj);

	Session* This = getHandle<Session>(env, thisObj);

	if (This == nullptr)
		return 0;
	return This->retriesLeft();
}

/*
* Class:     com_tecsec_OpenVEIL_Session
* Method:    getIsValid
* Signature: ()Z
*/
JNIEXPORT jboolean JNICALL Java_com_tecsec_OpenVEIL_Session_getIsValid
(JNIEnv *env, jobject thisObj)
{
	// Get a reference to this object's class
	jclass thisClass = env->GetObjectClass(thisObj);

	Session* This = getHandle<Session>(env, thisObj);

	if (This == nullptr)
		return JNI_FALSE;
	return This->isValid() ? JNI_TRUE : JNI_FALSE;
}

/*
* Class:     com_tecsec_OpenVEIL_Session
* Method:    duplicate
* Signature: ()Lcom/tecsec/OpenVEIL/Session;
*/
JNIEXPORT jobject JNICALL Java_com_tecsec_OpenVEIL_Session_duplicate
(JNIEnv *env, jobject thisObj)
{
	// Get a reference to this object's class
	jclass thisClass = env->GetObjectClass(thisObj);

	Session* This = getHandle<Session>(env, thisObj);

	if (This == nullptr)
		return nullptr;

	jclass cls = env->FindClass("com/tecsec/OpenVEIL/Session");
	jmethodID constructor = env->GetMethodID(cls, "<init>", "()V");
	jobject object = env->NewObject(cls, constructor);
	setHandle(env, object, This->duplicate());
	return object;
}

/*
* Class:     com_tecsec_OpenVEIL_Session
* Method:    encryptFileUsingFavorite
* Signature: (Lcom/tecsec/OpenVEIL/Favorite;Ljava/lang/String;ZLjava/lang/String;)Z
*/
JNIEXPORT jboolean JNICALL Java_com_tecsec_OpenVEIL_Session_encryptFileUsingFavorite
(JNIEnv *env, jobject thisObj, jobject fav, jstring sourceFile, jboolean compress, jstring destFile)
{
	// Get a reference to this object's class
	jclass thisClass = env->GetObjectClass(thisObj);

	Session* This = getHandle<Session>(env, thisObj);
	Favorite* Fav = getHandle<Favorite>(env, fav);

	if (This == nullptr)
		return JNI_FALSE;

	try
	{
		return This->encryptFileUsingFavorite(Fav, jstringToTsAscii(env, sourceFile), compress, jstringToTsAscii(env, destFile)) ? JNI_TRUE : JNI_FALSE;
	}
	catch (tsAscii &ex)
	{
		THROW_JAVA_EXCEPTION(ex.c_str());
		return JNI_FALSE;
	}
}

/*
* Class:     com_tecsec_OpenVEIL_Session
* Method:    decryptFile
* Signature: (Ljava/lang/String;Ljava/lang/String;)Z
*/
JNIEXPORT jboolean JNICALL Java_com_tecsec_OpenVEIL_Session_decryptFile
(JNIEnv *env, jobject thisObj, jstring sourceFile, jstring destFile)
{
	// Get a reference to this object's class
	jclass thisClass = env->GetObjectClass(thisObj);

	Session* This = getHandle<Session>(env, thisObj);

	if (This == nullptr)
		return JNI_FALSE;

	try
	{
		return This->decryptFile(jstringToTsAscii(env, sourceFile), jstringToTsAscii(env, destFile)) ? JNI_TRUE : JNI_FALSE;
	}
	catch (tsAscii &ex)
	{
		THROW_JAVA_EXCEPTION(ex.c_str());
		return JNI_FALSE;
	}
}

/*
* Class:     com_tecsec_OpenVEIL_Session
* Method:    encryptDataUsingFavorite
* Signature: (Lcom/tecsec/OpenVEIL/Favorite;[BZ)[B
*/
JNIEXPORT jbyteArray JNICALL Java_com_tecsec_OpenVEIL_Session_encryptDataUsingFavorite
(JNIEnv *env, jobject thisObj, jobject fav, jbyteArray sourceData, jboolean compress)
{
	// Get a reference to this object's class
	jclass thisClass = env->GetObjectClass(thisObj);

	Session* This = getHandle<Session>(env, thisObj);
	Favorite* Fav = getHandle<Favorite>(env, fav);

	if (This == nullptr)
		return JNI_FALSE;

	try
	{
		return tsDataToJbyteArray(env, This->encryptDataUsingFavorite(Fav, jbyteArrayToTsData(env, sourceData), compress));
	}
	catch (tsAscii &ex)
	{
		THROW_JAVA_EXCEPTION(ex.c_str());
		return nullptr;
	}
}

/*
* Class:     com_tecsec_OpenVEIL_Session
* Method:    decryptData
* Signature: ([B)[B
*/
JNIEXPORT jbyteArray JNICALL Java_com_tecsec_OpenVEIL_Session_decryptData
(JNIEnv *env, jobject thisObj, jbyteArray sourceData)
{
	// Get a reference to this object's class
	jclass thisClass = env->GetObjectClass(thisObj);

	Session* This = getHandle<Session>(env, thisObj);

	if (This == nullptr)
		return JNI_FALSE;

	try
	{
		return tsDataToJbyteArray(env, This->decryptData(jbyteArrayToTsData(env, sourceData)));
	}
	catch (tsAscii &ex)
	{
		THROW_JAVA_EXCEPTION(ex.c_str());
		return nullptr;
	}
}

/*
* Class:     com_tecsec_OpenVEIL_Session
* Method:    initialize
* Signature: ()V
*/
JNIEXPORT void JNICALL Java_com_tecsec_OpenVEIL_Session_initialize
(JNIEnv *env, jobject thisObj)
{
	setHandle(env, thisObj, new Session());
}

/*
* Class:     com_tecsec_OpenVEIL_Session
* Method:    terminate
* Signature: ()V
*/
JNIEXPORT void JNICALL Java_com_tecsec_OpenVEIL_Session_terminate
(JNIEnv *env, jobject thisObj)
{
	Session* This = getHandle<Session>(env, thisObj);

	if (This != nullptr)
	{
		delete This;
		This = nullptr;
		setHandle(env, thisObj, This);
	}
}
