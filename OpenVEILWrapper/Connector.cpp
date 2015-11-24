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
#include "com_tecsec_OpenVEIL_Connector.h"
#include "OpenVEIL.h"
#include "handle.h"

class OpenVEILConnector
{
public:
	OpenVEILConnector()
	{
		conn = ::ServiceLocator()->try_get_instance<IKeyVEILConnector>("/KeyVEILConnector");
	}
	~OpenVEILConnector()
	{

	}
	int genericConnectToServer(const tsAscii& url, const tsAscii& username, const tsAscii& password)
	{
		if (!isReady())
		{
			return connStatus_NoServer;
		}
		return conn->genericConnectToServer(url.c_str(), username.c_str(), password.c_str());
	}
	int connectToServer(const tsAscii& url, const tsAscii& username, const tsAscii& password)
	{
		if (!isReady())
		{
			return connStatus_NoServer;
		}
		return conn->connect(url.c_str(), username.c_str(), password.c_str());
	}
	void disconnect()
	{
		if (isConnected())
		{
			conn->disconnect();
		}
	}
	bool isConnected()
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
	bool sendJsonRequest(const tsAscii& verb, const tsAscii& cmd, const tsAscii& inData, tsAscii& outData, int& status)
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
	bool sendBase64Request(const tsAscii& verb, const tsAscii& cmd, const tsAscii& inData, tsAscii& outData, int& status)
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
protected:
	std::shared_ptr<IKeyVEILConnector> conn;
private:
	bool isReady()
	{
		return !!conn;
	}
};

static tsAscii jstringToTsAscii(JNIEnv* env, jstring str)
{
	tsAscii tmp;

	const char *inCStr = env->GetStringUTFChars(str, NULL);
	tmp = inCStr;
	if (inCStr != nullptr)
		env->ReleaseStringUTFChars(str, inCStr);  // release resources
	return tmp;
}

/*
* Class:     com_tecsec_OpenVEIL_Connector
* Method:    genericConnectToServer
* Signature: (Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)I
*/
JNIEXPORT jint JNICALL Java_com_tecsec_OpenVEIL_Connector_genericConnectToServer
(JNIEnv *env, jobject thisObj, jstring _url, jstring _username, jstring _password)
{
	// Get a reference to this object's class
	jclass thisClass = env->GetObjectClass(thisObj);

	OpenVEILConnector* This = getHandle<OpenVEILConnector>(env, thisObj);

	if (This == nullptr)
		return -1;
	return This->genericConnectToServer(jstringToTsAscii(env, _url), jstringToTsAscii(env, _username), jstringToTsAscii(env, _password));
}

/*
* Class:     com_tecsec_OpenVEIL_Connector
* Method:    connectToServer
* Signature: (Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)I
*/
JNIEXPORT jint JNICALL Java_com_tecsec_OpenVEIL_Connector_connectToServer
(JNIEnv *env, jobject thisObj, jstring _url, jstring _username, jstring _password)
{
	// Get a reference to this object's class
	jclass thisClass = env->GetObjectClass(thisObj);

	OpenVEILConnector* This = getHandle<OpenVEILConnector>(env, thisObj);

	if (This == nullptr)
		return -1;
	return This->connectToServer(jstringToTsAscii(env, _url), jstringToTsAscii(env, _username), jstringToTsAscii(env, _password));
}

/*
* Class:     com_tecsec_OpenVEIL_Connector
* Method:    disconnect
* Signature: ()V
*/
JNIEXPORT void JNICALL Java_com_tecsec_OpenVEIL_Connector_disconnect
(JNIEnv *env, jobject thisObj)
{
	// Get a reference to this object's class
	jclass thisClass = env->GetObjectClass(thisObj);

	OpenVEILConnector* This = getHandle<OpenVEILConnector>(env, thisObj);
	if (This == nullptr)
		return;
	This->disconnect();
}

/*
* Class:     com_tecsec_OpenVEIL_Connector
* Method:    isConnected
* Signature: ()Z
*/
JNIEXPORT jboolean JNICALL Java_com_tecsec_OpenVEIL_Connector_isConnected
(JNIEnv *env, jobject thisObj)
{
	// Get a reference to this object's class
	jclass thisClass = env->GetObjectClass(thisObj);

	OpenVEILConnector* This = getHandle<OpenVEILConnector>(env, thisObj);
	if (This == nullptr)
		return JNI_FALSE;
	return This->isConnected() ? JNI_TRUE : JNI_FALSE;
}

/*
* Class:     com_tecsec_OpenVEIL_Connector
* Method:    sendJsonRequest
* Signature: (Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lcom/tecsec/OpenVEIL/RequestResults;)Z
*/
JNIEXPORT jboolean JNICALL Java_com_tecsec_OpenVEIL_Connector_sendJsonRequest
(JNIEnv *env, jobject thisObj, jstring _verb, jstring _cmd, jstring _inData, jobject _results)
{
	// Get a reference to this object's class
	jclass thisClass = env->GetObjectClass(thisObj);
	tsAscii outData;
	int status = 0;

	OpenVEILConnector* This = getHandle<OpenVEILConnector>(env, thisObj);
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
* Class:     com_tecsec_OpenVEIL_Connector
* Method:    sendBase64Request
* Signature: (Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lcom/tecsec/OpenVEIL/RequestResults;)Z
*/
JNIEXPORT jboolean JNICALL Java_com_tecsec_OpenVEIL_Connector_sendBase64Request
(JNIEnv *env, jobject thisObj, jstring _verb, jstring _cmd, jstring _inData, jobject _results)
{
	// Get a reference to this object's class
	jclass thisClass = env->GetObjectClass(thisObj);
	tsAscii outData;
	int status = 0;

	OpenVEILConnector* This = getHandle<OpenVEILConnector>(env, thisObj);
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
* Class:     com_tecsec_OpenVEIL_Connector
* Method:    initialize
* Signature: ()V
*/
JNIEXPORT void JNICALL Java_com_tecsec_OpenVEIL_Connector_initialize
(JNIEnv *env, jobject thisObj)
{
	setHandle(env, thisObj, new OpenVEILConnector());
}

/*
* Class:     com_tecsec_OpenVEIL_Connector
* Method:    terminate
* Signature: ()V
*/
JNIEXPORT void JNICALL Java_com_tecsec_OpenVEIL_Connector_terminate
(JNIEnv *env, jobject thisObj)
{
	OpenVEILConnector* This = getHandle<OpenVEILConnector>(env, thisObj);

	if (This != nullptr)
	{
		delete This;
		This = nullptr;
		setHandle(env, thisObj, This);
	}
}
