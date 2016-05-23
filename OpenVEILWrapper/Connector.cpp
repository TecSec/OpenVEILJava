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


#include "Connector.h"
#include "VEIL.h"
#include "handle.h"

#pragma region Connector
Connector::Connector()
{
	conn = ::ServiceLocator()->try_get_instance<IKeyVEILConnector>("/KeyVEILConnector");
}
Connector::~Connector()
{

}
void Connector::disconnect()
{
	if (isConnected())
	{
		conn->disconnect();
	}
}
bool Connector::isConnected()
{
	if (isReady())
	{
		return conn->isConnected();
	}
	else
	{
		return false;
	}
}
bool Connector::sendJsonRequest(const tsAscii& verb, const tsAscii& cmd, const tsAscii& inData, tsAscii& outData, int& status)
{
	outData.clear();
	status = 0;

	if (!isReady())
	{
		false;
	}

	JSONObject inDataTmp;
	JSONObject outDataTmp;

	if (inDataTmp.FromJSON(inData.c_str()) <= 0)
	{
		return false;
	}

	if (!conn->sendJsonRequest(verb.c_str(), cmd.c_str(), inDataTmp, outDataTmp, status))
	{
		outData = outDataTmp.ToJSON();
		return false;
	}

	outData = outDataTmp.ToJSON();
	return true;
}
bool Connector::sendBase64Request(const tsAscii& verb, const tsAscii& cmd, const tsAscii& inData, tsAscii& outData, int& status)
{
	outData.clear();
	status = 0;

	if (!isReady())
	{
		return false;
	}

	tsData inDataTmp(inData.c_str(), tsData::BASE64);
	tsData outDataTmp;

	if (!conn->sendRequest(verb.c_str(), cmd.c_str(), inDataTmp, outDataTmp, status))
	{
		outData = outDataTmp.ToBase64();
		return false;
	}

	outData = outDataTmp.ToBase64();
	return true;
}
bool Connector::sendRequest(const tsAscii& verb, const tsAscii& cmd, const tsData& inData, tsData& outData, int& status)
{
	outData.clear();
	status = 0;

	if (!isReady())
	{
		return false;
	}

	if (!conn->sendRequest(verb.c_str(), cmd.c_str(), inData, outData, status))
	{
		return false;
	}

	return true;
}
bool Connector::isReady()
{
	return !!conn;
}
#pragma endregion

#pragma region GenericConnector
GenericConnector::GenericConnector()
{
}
GenericConnector::~GenericConnector()
{
}
ConnectionStatus GenericConnector::connectToServer(const tsAscii& url, const tsAscii& username, const tsAscii& password)
{
	if (!isReady())
	{
		return connStatus_NoServer;
	}
	return conn->genericConnectToServer(url.c_str(), username.c_str(), password.c_str());
}
#pragma endregion

#pragma region KeyVEILConnector
KeyVEILConnector::KeyVEILConnector()
{
}
KeyVEILConnector::~KeyVEILConnector()
{
}
ConnectionStatus KeyVEILConnector::connectToServer(const tsAscii& url, const tsAscii& username, const tsAscii& password)
{
	if (!isReady())
	{
		return connStatus_NoServer;
	}
	return conn->connect(url.c_str(), username.c_str(), password.c_str());
}
bool KeyVEILConnector::refresh()
{
	if (!isReady())
		return false;
	return conn->refresh();
}
size_t KeyVEILConnector::tokenCount()
{
	if (!isReady())
		return 0;
	return conn->tokenCount();
}
Token* KeyVEILConnector::tokenByIndex(size_t index)
{
	if (!isReady())
		return nullptr;
	return new Token(conn->token(index));
}
Token* KeyVEILConnector::tokenByName(const tsAscii& tokenName)
{
	if (!isReady())
		return nullptr;
	return new Token(conn->token(tsAscii(tokenName.c_str())));
}
Token* KeyVEILConnector::tokenBySerialNumber(const tsData& serialNumber)
{
	if (!isReady())
		return nullptr;

	return new Token(conn->token(serialNumber));
}
Token* KeyVEILConnector::tokenById(const tsAscii& id)
{
	if (!isReady())
		return nullptr;
	return new Token(conn->token(ToGuid()(tsAscii(id.c_str()))));
}
size_t KeyVEILConnector::favoriteCount()
{
	if (!isReady())
		return 0;
	return conn->favoriteCount();
}
Favorite* KeyVEILConnector::favoriteByIndex(size_t index)
{
	if (!isReady())
		return nullptr;
	return new Favorite(conn->favorite(index));
}
Favorite* KeyVEILConnector::favoriteByName(const tsAscii& name)
{
	if (!isReady())
		return nullptr;
	return new Favorite(conn->favorite(tsAscii(name.c_str())));
}
Favorite* KeyVEILConnector::favoriteById(const tsAscii& id)
{
	if (!isReady())
		return nullptr;
	return new Favorite(conn->favorite(ToGuid()(tsAscii(id.c_str()))));
}
tsAscii KeyVEILConnector::createFavorite(Token* token, const tsData& headerData, const tsAscii& name)
{
	if (!isReady())
		return "";
	return ToString()(conn->CreateFavorite(token->handle(), headerData, name));
}
tsAscii KeyVEILConnector::createFavorite(const tsAscii& tokenId, const tsData& headerData, const tsAscii& name)
{
	if (!isReady())
		return "";
	return ToString()(conn->CreateFavorite(ToGuid()(tokenId), headerData, name));
}
tsAscii KeyVEILConnector::createFavorite(const tsData& tokenSerial, const tsData& headerData, const tsAscii& name)
{
	if (!isReady())
		return "";
	return ToString()(conn->CreateFavorite(tokenSerial, headerData, name));
}
bool KeyVEILConnector::DeleteFavorite(const tsAscii& id)
{
	if (!isReady())
		return false;
	return conn->DeleteFavorite(ToGuid()(tsAscii(id.c_str())));
}
bool KeyVEILConnector::UpdateFavoriteName(const tsAscii& id, const tsAscii& name)
{
	if (!isReady())
		return false;
	return conn->UpdateFavoriteName(ToGuid()(tsAscii(id.c_str())), name.c_str());
}
bool KeyVEILConnector::UpdateFavorite(const tsAscii& id, const tsData& setTo)
{
	if (!isReady())
		return false;
	return conn->UpdateFavorite(ToGuid()(id), setTo);
}
size_t KeyVEILConnector::tokenCountForEnterpriseId(const tsAscii& enterpriseId)
{
	if (!isReady())
		return 0;
	return conn->tokenCountForEnterprise(ToGuid()(tsAscii(enterpriseId.c_str())));
}
Token* KeyVEILConnector::tokenForEnterprise(const tsAscii& enterpriseId, size_t index)
{
	if (!isReady())
		return nullptr;
	return new Token(conn->tokenForEnterprise(ToGuid()(tsAscii(enterpriseId.c_str())), index));
}
size_t KeyVEILConnector::favoriteCountForEnterprise(const tsAscii& enterpriseId)
{
	if (!isReady())
		return 0;
	return conn->favoriteCountForEnterprise(ToGuid()(tsAscii(enterpriseId.c_str())));
}
Favorite* KeyVEILConnector::favoriteForEnterprise(const tsAscii& enterpriseId, size_t index)
{
	if (!isReady())
		return nullptr;
	return new Favorite(conn->favoriteForEnterprise(ToGuid()(tsAscii(enterpriseId.c_str())), index));
}

#pragma endregion

tsAscii jstringToTsAscii(JNIEnv* env, jstring str)
{
	tsAscii tmp;

	const char *inCStr = env->GetStringUTFChars(str, NULL);
	tmp = inCStr;
	if (inCStr != nullptr)
		env->ReleaseStringUTFChars(str, inCStr);  // release resources
	return tmp;
}
jobject ConnectionStatusToJava(JNIEnv* env, ConnectionStatus value)
{
	jclass clSTATUS = env->FindClass("com/tecsec/OpenVEIL/ConnectionStatus");
	jfieldID fieldId = 0;
	switch (value)
	{
	case connStatus_BadAuth:
		fieldId = env->GetStaticFieldID(clSTATUS, "BADAUTH", "Lcom/tecsec/OpenVEIL/ConnectionStatus;");
		break;
	case connStatus_Connected:
		fieldId = env->GetStaticFieldID(clSTATUS, "CONNECTED", "Lcom/tecsec/OpenVEIL/ConnectionStatus;");
		break;
	case connStatus_NoServer:
		fieldId = env->GetStaticFieldID(clSTATUS, "NOSERVER", "Lcom/tecsec/OpenVEIL/ConnectionStatus;");
		break;
	case connStatus_WrongProtocol:
		fieldId = env->GetStaticFieldID(clSTATUS, "WRONGPROTOCOL", "Lcom/tecsec/OpenVEIL/ConnectionStatus;");
		break;
	case connStatus_UrlBad:
		fieldId = env->GetStaticFieldID(clSTATUS, "URLBAD", "Lcom/tecsec/OpenVEIL/ConnectionStatus;");
		break;
	}
	return env->GetStaticObjectField(clSTATUS, fieldId);
}

jstring tsAsciiToJstring(JNIEnv* env, const tsAscii& str)
{
	return env->NewStringUTF(str.c_str());
}

jbyteArray tsDataToJbyteArray(JNIEnv* env, const tsData& value)
{
	jbyteArray b = env->NewByteArray((jsize)value.size());

	if (value.size() > 0)
	{
		env->SetByteArrayRegion(b, 0, (jsize)value.size(), (const jbyte*)value.c_str());
	}
	return b;
}
tsData jbyteArrayToTsData(JNIEnv* env, jbyteArray value)
{
	tsData tmp;
	int size = env->GetArrayLength(value);

	tmp.resize(size);
	if (size > 0)
	{
		env->GetByteArrayRegion(value, 0, size, (jbyte*)tmp.rawData());
	}
	return tmp;
}
/*
* Class:     com_tecsec_OpenVEIL_GenericConnector
* Method:    connectToServer
* Signature: (Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)I
*/
JNIEXPORT jobject JNICALL Java_com_tecsec_OpenVEIL_GenericConnector_connectToServer(JNIEnv *env, jobject thisObj, jstring _url, jstring _username, jstring _password)
{
	// Get a reference to this object's class
	jclass thisClass = env->GetObjectClass(thisObj);

	GenericConnector* This = getHandle<GenericConnector>(env, thisObj);

	if (This == nullptr)
	{
		THROW_JAVA_EXCEPTION("Invalid GenericConnector");
		return nullptr;
	}

	return ConnectionStatusToJava(env, This->connectToServer(jstringToTsAscii(env, _url), jstringToTsAscii(env, _username), jstringToTsAscii(env, _password)));
}

/*
* Class:     com_tecsec_OpenVEIL_GenericConnector
* Method:    disconnect
* Signature: ()V
*/
JNIEXPORT void JNICALL Java_com_tecsec_OpenVEIL_GenericConnector_disconnect(JNIEnv *env, jobject thisObj)
{
	// Get a reference to this object's class
	jclass thisClass = env->GetObjectClass(thisObj);

	GenericConnector* This = getHandle<GenericConnector>(env, thisObj);
	if (This == nullptr)
		return;
	This->disconnect();
}

/*
* Class:     com_tecsec_OpenVEIL_GenericConnector
* Method:    isConnected
* Signature: ()Z
*/
JNIEXPORT jboolean JNICALL Java_com_tecsec_OpenVEIL_GenericConnector_isConnected(JNIEnv *env, jobject thisObj)
{
	// Get a reference to this object's class
	jclass thisClass = env->GetObjectClass(thisObj);

	GenericConnector* This = getHandle<GenericConnector>(env, thisObj);
	if (This == nullptr)
		return JNI_FALSE;
	return This->isConnected() ? JNI_TRUE : JNI_FALSE;
}

/*
* Class:     com_tecsec_OpenVEIL_GenericConnector
* Method:    sendJsonRequest
* Signature: (Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lcom/tecsec/OpenVEIL/RequestResults;)Z
*/
JNIEXPORT jboolean JNICALL Java_com_tecsec_OpenVEIL_GenericConnector_sendJsonRequest(JNIEnv *env, jobject thisObj, jstring _verb, jstring _cmd, jstring _inData, jobject _results)
{
	// Get a reference to this object's class
	jclass thisClass = env->GetObjectClass(thisObj);
	tsAscii outData;
	int status = 0;

	GenericConnector* This = getHandle<GenericConnector>(env, thisObj);
	if (This == nullptr)
		return JNI_FALSE;

	if (!This->sendJsonRequest(jstringToTsAscii(env, _verb), jstringToTsAscii(env, _cmd), jstringToTsAscii(env, _inData), outData, status))
	{
		setString(env, _results, "outData", outData);
		setInt(env, _results, "status", status);
		return JNI_FALSE;
	}
	setString(env, _results, "outData", outData);
	setInt(env, _results, "status", status);
	return JNI_TRUE;
}

/*
* Class:     com_tecsec_OpenVEIL_GenericConnector
* Method:    sendBase64Request
* Signature: (Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lcom/tecsec/OpenVEIL/RequestResults;)Z
*/
JNIEXPORT jboolean JNICALL Java_com_tecsec_OpenVEIL_GenericConnector_sendBase64Request(JNIEnv *env, jobject thisObj, jstring _verb, jstring _cmd, jstring _inData, jobject _results)
{
	// Get a reference to this object's class
	jclass thisClass = env->GetObjectClass(thisObj);
	tsAscii outData;
	int status = 0;

	GenericConnector* This = getHandle<GenericConnector>(env, thisObj);
	if (This == nullptr)
		return JNI_FALSE;

	if (!This->sendBase64Request(jstringToTsAscii(env, _verb), jstringToTsAscii(env, _cmd), jstringToTsAscii(env, _inData), outData, status))
	{
		setString(env, _results, "outData", outData);
		setInt(env, _results, "status", status);
		return JNI_FALSE;
	}
	setString(env, _results, "outData", outData);
	setInt(env, _results, "status", status);
	return JNI_TRUE;
}

/*
* Class:     com_tecsec_OpenVEIL_GenericConnector
* Method:    sendRequest
* Signature: (Ljava/lang/String;Ljava/lang/String;[BLcom/tecsec/OpenVEIL/RequestResultsBinary;)Z
*/
JNIEXPORT jboolean JNICALL Java_com_tecsec_OpenVEIL_GenericConnector_sendRequest(JNIEnv *env, jobject thisObj, jstring _verb, jstring _cmd, jbyteArray _inData, jobject _results)
{
	// Get a reference to this object's class
	jclass thisClass = env->GetObjectClass(thisObj);
	tsData outData;
	int status = 0;

	GenericConnector* This = getHandle<GenericConnector>(env, thisObj);
	if (This == nullptr)
		return JNI_FALSE;

	if (!This->sendRequest(jstringToTsAscii(env, _verb), jstringToTsAscii(env, _cmd), jbyteArrayToTsData(env, _inData), outData, status))
	{
		setJByteArray(env, _results, "outData", outData);
		setInt(env, _results, "status", status);
		return JNI_FALSE;
	}
	setJByteArray(env, _results, "outData", outData);
	setInt(env, _results, "status", status);
	return JNI_TRUE;
}

/*
* Class:     com_tecsec_OpenVEIL_GenericConnector
* Method:    initialize
* Signature: ()V
*/
JNIEXPORT void JNICALL Java_com_tecsec_OpenVEIL_GenericConnector_initialize(JNIEnv *env, jobject thisObj)
{
	setHandle(env, thisObj, new GenericConnector());
}

/*
* Class:     com_tecsec_OpenVEIL_GenericConnector
* Method:    terminate
* Signature: ()V
*/
JNIEXPORT void JNICALL Java_com_tecsec_OpenVEIL_GenericConnector_terminate(JNIEnv *env, jobject thisObj)
{
	GenericConnector* This = getHandle<GenericConnector>(env, thisObj);

	if (This != nullptr)
	{
		delete This;
		This = nullptr;
		setHandle(env, thisObj, This);
	}
}



/*
* Class:     com_tecsec_OpenVEIL_KeyVEILConnector
* Method:    connectToServer
* Signature: (Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)I
*/
JNIEXPORT jobject JNICALL Java_com_tecsec_OpenVEIL_KeyVEILConnector_connectToServer(JNIEnv *env, jobject thisObj, jstring _url, jstring _username, jstring _password)
{
	// Get a reference to this object's class
	jclass thisClass = env->GetObjectClass(thisObj);

	KeyVEILConnector* This = getHandle<KeyVEILConnector>(env, thisObj);

	if (This == nullptr)
	{
		THROW_JAVA_EXCEPTION("Invalid KeyVEILConnector");
		return nullptr;
	}

	return ConnectionStatusToJava(env, This->connectToServer(jstringToTsAscii(env, _url), jstringToTsAscii(env, _username), jstringToTsAscii(env, _password)));
}

/*
* Class:     com_tecsec_OpenVEIL_KeyVEILConnector
* Method:    disconnect
* Signature: ()V
*/
JNIEXPORT void JNICALL Java_com_tecsec_OpenVEIL_KeyVEILConnector_disconnect(JNIEnv *env, jobject thisObj)
{
	// Get a reference to this object's class
	jclass thisClass = env->GetObjectClass(thisObj);

	KeyVEILConnector* This = getHandle<KeyVEILConnector>(env, thisObj);
	if (This == nullptr)
		return;
	This->disconnect();
}
/*
* Class:     com_tecsec_OpenVEIL_KeyVEILConnector
* Method:    isConnected
* Signature: ()Z
*/
JNIEXPORT jboolean JNICALL Java_com_tecsec_OpenVEIL_KeyVEILConnector_isConnected(JNIEnv *env, jobject thisObj)
{
	// Get a reference to this object's class
	jclass thisClass = env->GetObjectClass(thisObj);

	KeyVEILConnector* This = getHandle<KeyVEILConnector>(env, thisObj);
	if (This == nullptr)
		return JNI_FALSE;
	return This->isConnected() ? JNI_TRUE : JNI_FALSE;
}
/*
* Class:     com_tecsec_OpenVEIL_KeyVEILConnector
* Method:    sendJsonRequest
* Signature: (Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lcom/tecsec/OpenVEIL/RequestResults;)Z
*/
JNIEXPORT jboolean JNICALL Java_com_tecsec_OpenVEIL_KeyVEILConnector_sendJsonRequest(JNIEnv *env, jobject thisObj, jstring _verb, jstring _cmd, jstring _inData, jobject _results)
{
	// Get a reference to this object's class
	jclass thisClass = env->GetObjectClass(thisObj);
	tsAscii outData;
	int status = 0;

	KeyVEILConnector* This = getHandle<KeyVEILConnector>(env, thisObj);
	if (This == nullptr)
		return JNI_FALSE;

	if (!This->sendJsonRequest(jstringToTsAscii(env, _verb), jstringToTsAscii(env, _cmd), jstringToTsAscii(env, _inData), outData, status))
	{
		setString(env, _results, "outData", outData);
		setInt(env, _results, "status", status);
		return JNI_FALSE;
	}
	setString(env, _results, "outData", outData);
	setInt(env, _results, "status", status);
	return JNI_TRUE;
}
/*
* Class:     com_tecsec_OpenVEIL_KeyVEILConnector
* Method:    sendBase64Request
* Signature: (Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lcom/tecsec/OpenVEIL/RequestResults;)Z
*/
JNIEXPORT jboolean JNICALL Java_com_tecsec_OpenVEIL_KeyVEILConnector_sendBase64Request(JNIEnv *env, jobject thisObj, jstring _verb, jstring _cmd, jstring _inData, jobject _results)
{
	// Get a reference to this object's class
	jclass thisClass = env->GetObjectClass(thisObj);
	tsAscii outData;
	int status = 0;

	KeyVEILConnector* This = getHandle<KeyVEILConnector>(env, thisObj);
	if (This == nullptr)
		return JNI_FALSE;

	if (!This->sendBase64Request(jstringToTsAscii(env, _verb), jstringToTsAscii(env, _cmd), jstringToTsAscii(env, _inData), outData, status))
	{
		setString(env, _results, "outData", outData);
		setInt(env, _results, "status", status);
		return JNI_FALSE;
	}
	setString(env, _results, "outData", outData);
	setInt(env, _results, "status", status);
	return JNI_TRUE;
}

/*
* Class:     com_tecsec_OpenVEIL_GenericConnector
* Method:    sendRequest
* Signature: (Ljava/lang/String;Ljava/lang/String;[BLcom/tecsec/OpenVEIL/RequestResultsBinary;)Z
*/
JNIEXPORT jboolean JNICALL Java_com_tecsec_OpenVEIL_KeyVEILConnector_sendRequest(JNIEnv *env, jobject thisObj, jstring _verb, jstring _cmd, jbyteArray _inData, jobject _results)
{
	// Get a reference to this object's class
	jclass thisClass = env->GetObjectClass(thisObj);
	tsData outData;
	int status = 0;

	KeyVEILConnector* This = getHandle<KeyVEILConnector>(env, thisObj);
	if (This == nullptr)
		return JNI_FALSE;

	if (!This->sendRequest(jstringToTsAscii(env, _verb), jstringToTsAscii(env, _cmd), jbyteArrayToTsData(env, _inData), outData, status))
	{
		setJByteArray(env, _results, "outData", outData);
		setInt(env, _results, "status", status);
		return JNI_FALSE;
	}
	setJByteArray(env, _results, "outData", outData);
	setInt(env, _results, "status", status);
	return JNI_TRUE;
}

/*
* Class:     com_tecsec_OpenVEIL_KeyVEILConnector
* Method:    initialize
* Signature: ()V
*/
JNIEXPORT void JNICALL Java_com_tecsec_OpenVEIL_KeyVEILConnector_initialize(JNIEnv *env, jobject thisObj)
{
	setHandle(env, thisObj, new KeyVEILConnector());
}
/*
* Class:     com_tecsec_OpenVEIL_KeyVEILConnector
* Method:    terminate
* Signature: ()V
*/
JNIEXPORT void JNICALL Java_com_tecsec_OpenVEIL_KeyVEILConnector_terminate(JNIEnv *env, jobject thisObj)
{
	KeyVEILConnector* This = getHandle<KeyVEILConnector>(env, thisObj);

	if (This != nullptr)
	{
		delete This;
		This = nullptr;
		setHandle(env, thisObj, This);
	}
}

/*
* Class:     com_tecsec_OpenVEIL_KeyVEILConnector
* Method:    refresh
* Signature: ()Z
*/
JNIEXPORT jboolean JNICALL Java_com_tecsec_OpenVEIL_KeyVEILConnector_refresh(JNIEnv *env, jobject thisObj)
{
	// Get a reference to this object's class
	jclass thisClass = env->GetObjectClass(thisObj);

	KeyVEILConnector* This = getHandle<KeyVEILConnector>(env, thisObj);
	if (This == nullptr)
		return JNI_FALSE;
	return This->refresh() ? JNI_TRUE : JNI_FALSE;
}
/*
* Class:     com_tecsec_OpenVEIL_KeyVEILConnector
* Method:    tokenCount
* Signature: ()I
*/
JNIEXPORT jint JNICALL Java_com_tecsec_OpenVEIL_KeyVEILConnector_tokenCount(JNIEnv *env, jobject thisObj)
{
	// Get a reference to this object's class
	jclass thisClass = env->GetObjectClass(thisObj);

	KeyVEILConnector* This = getHandle<KeyVEILConnector>(env, thisObj);
	if (This == nullptr)
		return 0;
	return (jint)This->tokenCount();
}

/*
* Class:     com_tecsec_OpenVEIL_KeyVEILConnector
* Method:    tokenByIndex
* Signature: (I)Lcom/tecsec/OpenVEIL/Token;
*/
JNIEXPORT jobject JNICALL Java_com_tecsec_OpenVEIL_KeyVEILConnector_tokenByIndex(JNIEnv *env, jobject thisObj, jint index)
{
	// Get a reference to this object's class
	jclass thisClass = env->GetObjectClass(thisObj);

	KeyVEILConnector* This = getHandle<KeyVEILConnector>(env, thisObj);

	if (This == nullptr)
		return nullptr;

	jclass cls = env->FindClass("com/tecsec/OpenVEIL/Token");
	jmethodID constructor = env->GetMethodID(cls, "<init>", "()V");
	jobject object = env->NewObject(cls, constructor);
	setHandle(env, object, This->tokenByIndex(index));
	return object;
}

/*
* Class:     com_tecsec_OpenVEIL_KeyVEILConnector
* Method:    tokenByName
* Signature: (Ljava/lang/String;)Lcom/tecsec/OpenVEIL/Token;
*/
JNIEXPORT jobject JNICALL Java_com_tecsec_OpenVEIL_KeyVEILConnector_tokenByName(JNIEnv *env, jobject thisObj, jstring name)
{
	// Get a reference to this object's class
	jclass thisClass = env->GetObjectClass(thisObj);

	KeyVEILConnector* This = getHandle<KeyVEILConnector>(env, thisObj);

	if (This == nullptr)
		return nullptr;

	jclass cls = env->FindClass("com/tecsec/OpenVEIL/Token");
	jmethodID constructor = env->GetMethodID(cls, "<init>", "()V");
	jobject object = env->NewObject(cls, constructor);
	setHandle(env, object, This->tokenByName(jstringToTsAscii(env, name)));
	return object;
}

/*
* Class:     com_tecsec_OpenVEIL_KeyVEILConnector
* Method:    tokenBySerialNumber
* Signature: (Ljava/lang/String;)Lcom/tecsec/OpenVEIL/Token;
*/
JNIEXPORT jobject JNICALL Java_com_tecsec_OpenVEIL_KeyVEILConnector_tokenBySerialNumber___3B(JNIEnv *env, jobject thisObj, jbyteArray serialNumber)
{
	// Get a reference to this object's class
	jclass thisClass = env->GetObjectClass(thisObj);

	KeyVEILConnector* This = getHandle<KeyVEILConnector>(env, thisObj);

	if (This == nullptr)
		return nullptr;

	jclass cls = env->FindClass("com/tecsec/OpenVEIL/Token");
	jmethodID constructor = env->GetMethodID(cls, "<init>", "()V");
	jobject object = env->NewObject(cls, constructor);
	setHandle(env, object, This->tokenBySerialNumber(jbyteArrayToTsData(env, serialNumber)));
	return object;
}

/*
* Class:     com_tecsec_OpenVEIL_KeyVEILConnector
* Method:    tokenBySerialNumber
* Signature: (Ljava/lang/String;)Lcom/tecsec/OpenVEIL/Token;
*/
JNIEXPORT jobject JNICALL Java_com_tecsec_OpenVEIL_KeyVEILConnector_tokenBySerialNumber__Ljava_lang_String_2(JNIEnv *env, jobject thisObj, jstring serialNumber)
{
	// Get a reference to this object's class
	jclass thisClass = env->GetObjectClass(thisObj);

	KeyVEILConnector* This = getHandle<KeyVEILConnector>(env, thisObj);

	if (This == nullptr)
		return nullptr;

	jclass cls = env->FindClass("com/tecsec/OpenVEIL/Token");
	jmethodID constructor = env->GetMethodID(cls, "<init>", "()V");
	jobject object = env->NewObject(cls, constructor);
	setHandle(env, object, This->tokenBySerialNumber(jstringToTsAscii(env, serialNumber).HexToData()));
	return object;
}


/*
* Class:     com_tecsec_OpenVEIL_KeyVEILConnector
* Method:    tokenById
* Signature: (Ljava/lang/String;)Lcom/tecsec/OpenVEIL/Token;
*/
JNIEXPORT jobject JNICALL Java_com_tecsec_OpenVEIL_KeyVEILConnector_tokenById(JNIEnv *env, jobject thisObj, jstring id)
{
	// Get a reference to this object's class
	jclass thisClass = env->GetObjectClass(thisObj);

	KeyVEILConnector* This = getHandle<KeyVEILConnector>(env, thisObj);

	if (This == nullptr)
		return nullptr;

	jclass cls = env->FindClass("com/tecsec/OpenVEIL/Token");
	jmethodID constructor = env->GetMethodID(cls, "<init>", "()V");
	jobject object = env->NewObject(cls, constructor);
	setHandle(env, object, This->tokenById(jstringToTsAscii(env, id)));
	return object;
}

/*
* Class:     com_tecsec_OpenVEIL_KeyVEILConnector
* Method:    favoriteCount
* Signature: ()I
*/
JNIEXPORT jint JNICALL Java_com_tecsec_OpenVEIL_KeyVEILConnector_favoriteCount(JNIEnv *env, jobject thisObj)
{
	// Get a reference to this object's class
	jclass thisClass = env->GetObjectClass(thisObj);

	KeyVEILConnector* This = getHandle<KeyVEILConnector>(env, thisObj);
	if (This == nullptr)
		return 0;
	return (jint)This->favoriteCount();
}

/*
* Class:     com_tecsec_OpenVEIL_KeyVEILConnector
* Method:    favoriteByIndex
* Signature: (I)Lcom/tecsec/OpenVEIL/Favorite;
*/
JNIEXPORT jobject JNICALL Java_com_tecsec_OpenVEIL_KeyVEILConnector_favoriteByIndex(JNIEnv *env, jobject thisObj, jint index)
{
	// Get a reference to this object's class
	jclass thisClass = env->GetObjectClass(thisObj);

	KeyVEILConnector* This = getHandle<KeyVEILConnector>(env, thisObj);

	if (This == nullptr)
		return nullptr;

	jclass cls = env->FindClass("com/tecsec/OpenVEIL/Favorite");
	jmethodID constructor = env->GetMethodID(cls, "<init>", "()V");
	jobject object = env->NewObject(cls, constructor);
	setHandle(env, object, This->favoriteByIndex(index));
	return object;
}

/*
* Class:     com_tecsec_OpenVEIL_KeyVEILConnector
* Method:    favoriteByName
* Signature: (Ljava/lang/String;)Lcom/tecsec/OpenVEIL/Favorite;
*/
JNIEXPORT jobject JNICALL Java_com_tecsec_OpenVEIL_KeyVEILConnector_favoriteByName(JNIEnv *env, jobject thisObj, jstring name)
{
	// Get a reference to this object's class
	jclass thisClass = env->GetObjectClass(thisObj);

	KeyVEILConnector* This = getHandle<KeyVEILConnector>(env, thisObj);

	if (This == nullptr)
		return nullptr;

	jclass cls = env->FindClass("com/tecsec/OpenVEIL/Favorite");
	jmethodID constructor = env->GetMethodID(cls, "<init>", "()V");
	jobject object = env->NewObject(cls, constructor);
	setHandle(env, object, This->favoriteByName(jstringToTsAscii(env, name)));
	return object;
}

/*
* Class:     com_tecsec_OpenVEIL_KeyVEILConnector
* Method:    favoriteById
* Signature: (Ljava/lang/String;)Lcom/tecsec/OpenVEIL/Favorite;
*/
JNIEXPORT jobject JNICALL Java_com_tecsec_OpenVEIL_KeyVEILConnector_favoriteById(JNIEnv *env, jobject thisObj, jstring id)
{
	// Get a reference to this object's class
	jclass thisClass = env->GetObjectClass(thisObj);

	KeyVEILConnector* This = getHandle<KeyVEILConnector>(env, thisObj);

	if (This == nullptr)
		return nullptr;

	jclass cls = env->FindClass("com/tecsec/OpenVEIL/Favorite");
	jmethodID constructor = env->GetMethodID(cls, "<init>", "()V");
	jobject object = env->NewObject(cls, constructor);
	setHandle(env, object, This->favoriteById(jstringToTsAscii(env, id)));
	return object;
}

/*
* Class:     com_tecsec_OpenVEIL_KeyVEILConnector
* Method:    CreateFavorite
* Signature: (Lcom/tecsec/OpenVEIL/Token;[BLjava/lang/String;)Ljava/lang/String;
*/
JNIEXPORT jstring JNICALL Java_com_tecsec_OpenVEIL_KeyVEILConnector_CreateFavorite__Lcom_tecsec_OpenVEIL_Token_2_3BLjava_lang_String_2
(JNIEnv *env, jobject thisObj, jobject token, jbyteArray headerData, jstring name)
{
	// Get a reference to this object's class
	jclass thisClass = env->GetObjectClass(thisObj);

	KeyVEILConnector* This = getHandle<KeyVEILConnector>(env, thisObj);
	Token* tok = getHandle<Token>(env, token);

	if (This == nullptr)
		return nullptr;
	return tsAsciiToJstring(env, This->createFavorite(tok, jbyteArrayToTsData(env, headerData), jstringToTsAscii(env, name)));
}

/*
* Class:     com_tecsec_OpenVEIL_KeyVEILConnector
* Method:    CreateFavorite
* Signature: (Ljava/lang/String;[BLjava/lang/String;)Ljava/lang/String;
*/
JNIEXPORT jstring JNICALL Java_com_tecsec_OpenVEIL_KeyVEILConnector_CreateFavorite__Ljava_lang_String_2_3BLjava_lang_String_2
(JNIEnv *env, jobject thisObj, jstring tokenId, jbyteArray headerData, jstring name)
{
	// Get a reference to this object's class
	jclass thisClass = env->GetObjectClass(thisObj);

	KeyVEILConnector* This = getHandle<KeyVEILConnector>(env, thisObj);

	if (This == nullptr)
		return nullptr;
	return tsAsciiToJstring(env, This->createFavorite(jstringToTsAscii(env, tokenId), jbyteArrayToTsData(env, headerData), jstringToTsAscii(env, name)));
}

/*
* Class:     com_tecsec_OpenVEIL_KeyVEILConnector
* Method:    CreateFavorite
* Signature: ([B[BLjava/lang/String;)Ljava/lang/String;
*/
JNIEXPORT jstring JNICALL Java_com_tecsec_OpenVEIL_KeyVEILConnector_CreateFavorite___3B_3BLjava_lang_String_2
(JNIEnv *env, jobject thisObj, jbyteArray serial, jbyteArray headerData, jstring name)
{
	// Get a reference to this object's class
	jclass thisClass = env->GetObjectClass(thisObj);

	KeyVEILConnector* This = getHandle<KeyVEILConnector>(env, thisObj);

	if (This == nullptr)
		return nullptr;
	return tsAsciiToJstring(env, This->createFavorite(jbyteArrayToTsData(env, serial), jbyteArrayToTsData(env, headerData), jstringToTsAscii(env, name)));
}

/*
* Class:     com_tecsec_OpenVEIL_KeyVEILConnector
* Method:    DeleteFavorite
* Signature: (Ljava/lang/String;)Z
*/
JNIEXPORT jboolean JNICALL Java_com_tecsec_OpenVEIL_KeyVEILConnector_DeleteFavorite(JNIEnv *env, jobject thisObj, jstring id)
{
	// Get a reference to this object's class
	jclass thisClass = env->GetObjectClass(thisObj);

	KeyVEILConnector* This = getHandle<KeyVEILConnector>(env, thisObj);
	if (This == nullptr)
		return JNI_FALSE;
	return This->DeleteFavorite(jstringToTsAscii(env, id)) ? JNI_TRUE : JNI_FALSE;
}

/*
* Class:     com_tecsec_OpenVEIL_KeyVEILConnector
* Method:    UpdateFavoriteName
* Signature: (Ljava/lang/String;Ljava/lang/String;)Z
*/
JNIEXPORT jboolean JNICALL Java_com_tecsec_OpenVEIL_KeyVEILConnector_UpdateFavoriteName(JNIEnv *env, jobject thisObj, jstring id, jstring name)
{
	// Get a reference to this object's class
	jclass thisClass = env->GetObjectClass(thisObj);

	KeyVEILConnector* This = getHandle<KeyVEILConnector>(env, thisObj);
	if (This == nullptr)
		return JNI_FALSE;
	return This->UpdateFavoriteName(jstringToTsAscii(env, id), jstringToTsAscii(env, name)) ? JNI_TRUE : JNI_FALSE;
}

/*
* Class:     com_tecsec_OpenVEIL_KeyVEILConnector
* Method:    UpdateFavorite
* Signature: (Ljava/lang/String;[B)Z
*/
JNIEXPORT jboolean JNICALL Java_com_tecsec_OpenVEIL_KeyVEILConnector_UpdateFavorite
(JNIEnv *env, jobject thisObj, jstring id, jbyteArray headerData)
{
	// Get a reference to this object's class
	jclass thisClass = env->GetObjectClass(thisObj);

	KeyVEILConnector* This = getHandle<KeyVEILConnector>(env, thisObj);
	if (This == nullptr)
		return JNI_FALSE;
	return This->UpdateFavorite(jstringToTsAscii(env, id), jbyteArrayToTsData(env, headerData)) ? JNI_TRUE : JNI_FALSE;
}

/*
* Class:     com_tecsec_OpenVEIL_KeyVEILConnector
* Method:    tokenCountForEnterpriseId
* Signature: (Ljava/lang/String;)I
*/
JNIEXPORT jint JNICALL Java_com_tecsec_OpenVEIL_KeyVEILConnector_tokenCountForEnterpriseId(JNIEnv *env, jobject thisObj, jstring enterpriseId)
{
	// Get a reference to this object's class
	jclass thisClass = env->GetObjectClass(thisObj);

	KeyVEILConnector* This = getHandle<KeyVEILConnector>(env, thisObj);
	if (This == nullptr)
		return 0;
	return (jint)This->tokenCountForEnterpriseId(jstringToTsAscii(env, enterpriseId));
}

/*
* Class:     com_tecsec_OpenVEIL_KeyVEILConnector
* Method:    tokenForEnterprise
* Signature: (Ljava/lang/String;I)Lcom/tecsec/OpenVEIL/Token;
*/
JNIEXPORT jobject JNICALL Java_com_tecsec_OpenVEIL_KeyVEILConnector_tokenForEnterprise(JNIEnv *env, jobject thisObj, jstring enterpriseId, jint index)
{
	// Get a reference to this object's class
	jclass thisClass = env->GetObjectClass(thisObj);

	KeyVEILConnector* This = getHandle<KeyVEILConnector>(env, thisObj);

	if (This == nullptr)
		return nullptr;

	jclass cls = env->FindClass("com/tecsec/OpenVEIL/Token");
	jmethodID constructor = env->GetMethodID(cls, "<init>", "()V");
	jobject object = env->NewObject(cls, constructor);
	setHandle(env, object, This->tokenForEnterprise(jstringToTsAscii(env, enterpriseId), index));
	return object;
}

/*
* Class:     com_tecsec_OpenVEIL_KeyVEILConnector
* Method:    favoriteCountForEnterprise
* Signature: (Ljava/lang/String;)I
*/
JNIEXPORT jint JNICALL Java_com_tecsec_OpenVEIL_KeyVEILConnector_favoriteCountForEnterprise(JNIEnv *env, jobject thisObj, jstring enterpriseId)
{
	// Get a reference to this object's class
	jclass thisClass = env->GetObjectClass(thisObj);

	KeyVEILConnector* This = getHandle<KeyVEILConnector>(env, thisObj);
	if (This == nullptr)
		return 0;
	return (jint)This->favoriteCountForEnterprise(jstringToTsAscii(env, enterpriseId));
}

/*
* Class:     com_tecsec_OpenVEIL_KeyVEILConnector
* Method:    favoriteForEnterprise
* Signature: (Ljava/lang/String;I)Lcom/tecsec/OpenVEIL/Favorite;
*/
JNIEXPORT jobject JNICALL Java_com_tecsec_OpenVEIL_KeyVEILConnector_favoriteForEnterprise(JNIEnv *env, jobject thisObj, jstring enterpriseId, jint index)
{
	// Get a reference to this object's class
	jclass thisClass = env->GetObjectClass(thisObj);

	KeyVEILConnector* This = getHandle<KeyVEILConnector>(env, thisObj);

	if (This == nullptr)
		return nullptr;

	jclass cls = env->FindClass("com/tecsec/OpenVEIL/Favorite");
	jmethodID constructor = env->GetMethodID(cls, "<init>", "()V");
	jobject object = env->NewObject(cls, constructor);
	setHandle(env, object, This->favoriteForEnterprise(jstringToTsAscii(env, enterpriseId), index));
	return object;
}

