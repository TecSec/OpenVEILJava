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
#include "Token.h"
#include "OpenVEIL.h"
#include "handle.h"

Token::Token()
{

}
Token::Token(std::shared_ptr<IToken> _tok) : _dataHolder(_tok)
{

}
Token::~Token()
{
	release();
}
void Token::release()
{
	_dataHolder.reset();
}
tsAscii Token::getTokenName()
{
	if (!isReady())
		return "";
	return handle()->tokenName().c_str();
}
bool Token::setTokenName(const tsAscii& setTo)
{
	if (!isReady())
		return false;
	return handle()->tokenName(setTo.c_str());
}
tsData Token::serialNumber()
{
	if (!isReady())
		return "";
	return handle()->serialNumber().ToHexString().c_str();
}
tsAscii Token::id()
{
	if (!isReady())
		return "";
	return ToString()(handle()->id()).c_str();
}
tsAscii Token::enterpriseName()
{
	if (!isReady())
		return "";
	return handle()->enterpriseName().c_str();
}
tsAscii Token::memberName()
{
	if (!isReady())
		return "";
	return handle()->memberName().c_str();
}
tsAscii Token::tokenType()
{
	if (!isReady())
		return "";
	return handle()->tokenType().c_str();
}
tsAscii Token::enterpriseId()
{
	if (!isReady())
		return "";
	return ToString()(handle()->enterpriseId()).c_str();
}
tsAscii Token::memberId()
{
	if (!isReady())
		return "";
	return ToString()(handle()->memberId()).c_str();
}
Session* Token::openSession()
{
	if (!isReady())
		return nullptr;
	return new Session(handle()->openSession());
}



/*
* Class:     com_tecsec_OpenVEIL_Token
* Method:    release
* Signature: ()V
*/
JNIEXPORT void JNICALL Java_com_tecsec_OpenVEIL_Token_release
(JNIEnv *env, jobject thisObj)
{
	// Get a reference to this object's class
	jclass thisClass = env->GetObjectClass(thisObj);

	Token* This = getHandle<Token>(env, thisObj);

	if (This == nullptr)
		return;
	This->release();
}

/*
* Class:     com_tecsec_OpenVEIL_Token
* Method:    getTokenName
* Signature: ()Ljava/lang/String;
*/
JNIEXPORT jstring JNICALL Java_com_tecsec_OpenVEIL_Token_getTokenName
(JNIEnv *env, jobject thisObj)
{
	// Get a reference to this object's class
	jclass thisClass = env->GetObjectClass(thisObj);

	Token* This = getHandle<Token>(env, thisObj);

	if (This == nullptr)
		return nullptr;
	return tsAsciiToJstring(env, This->getTokenName());
}

/*
* Class:     com_tecsec_OpenVEIL_Token
* Method:    setTokenName
* Signature: (Ljava/lang/String;)V
*/
JNIEXPORT void JNICALL Java_com_tecsec_OpenVEIL_Token_setTokenName
(JNIEnv *env, jobject thisObj, jstring name)
{
	// Get a reference to this object's class
	jclass thisClass = env->GetObjectClass(thisObj);

	Token* This = getHandle<Token>(env, thisObj);

	if (This == nullptr)
		return;
	This->setTokenName(jstringToTsAscii(env, name));
}

/*
* Class:     com_tecsec_OpenVEIL_Token
* Method:    getSerialNumber
* Signature: ()[B
*/
JNIEXPORT jbyteArray JNICALL Java_com_tecsec_OpenVEIL_Token_getSerialNumber
(JNIEnv *env, jobject thisObj)
{
	// Get a reference to this object's class
	jclass thisClass = env->GetObjectClass(thisObj);

	Token* This = getHandle<Token>(env, thisObj);

	if (This == nullptr)
		return nullptr;
	return tsDataToJbyteArray(env, This->serialNumber());
}

/*
* Class:     com_tecsec_OpenVEIL_Token
* Method:    getId
* Signature: ()Ljava/lang/String;
*/
JNIEXPORT jstring JNICALL Java_com_tecsec_OpenVEIL_Token_getId
(JNIEnv *env, jobject thisObj)
{
	// Get a reference to this object's class
	jclass thisClass = env->GetObjectClass(thisObj);

	Token* This = getHandle<Token>(env, thisObj);

	if (This == nullptr)
		return nullptr;
	return tsAsciiToJstring(env, This->id());
}

/*
* Class:     com_tecsec_OpenVEIL_Token
* Method:    getEnterpriseName
* Signature: ()Ljava/lang/String;
*/
JNIEXPORT jstring JNICALL Java_com_tecsec_OpenVEIL_Token_getEnterpriseName
(JNIEnv *env, jobject thisObj)
{
	// Get a reference to this object's class
	jclass thisClass = env->GetObjectClass(thisObj);

	Token* This = getHandle<Token>(env, thisObj);

	if (This == nullptr)
		return nullptr;
	return tsAsciiToJstring(env, This->enterpriseName());
}

/*
* Class:     com_tecsec_OpenVEIL_Token
* Method:    getMemberName
* Signature: ()Ljava/lang/String;
*/
JNIEXPORT jstring JNICALL Java_com_tecsec_OpenVEIL_Token_getMemberName
(JNIEnv *env, jobject thisObj)
{
	// Get a reference to this object's class
	jclass thisClass = env->GetObjectClass(thisObj);

	Token* This = getHandle<Token>(env, thisObj);

	if (This == nullptr)
		return nullptr;
	return tsAsciiToJstring(env, This->memberName());
}

/*
* Class:     com_tecsec_OpenVEIL_Token
* Method:    getTokenType
* Signature: ()Ljava/lang/String;
*/
JNIEXPORT jstring JNICALL Java_com_tecsec_OpenVEIL_Token_getTokenType
(JNIEnv *env, jobject thisObj)
{
	// Get a reference to this object's class
	jclass thisClass = env->GetObjectClass(thisObj);

	Token* This = getHandle<Token>(env, thisObj);

	if (This == nullptr)
		return nullptr;
	return tsAsciiToJstring(env, This->tokenType());
}

/*
* Class:     com_tecsec_OpenVEIL_Token
* Method:    getEnterpriseId
* Signature: ()Ljava/lang/String;
*/
JNIEXPORT jstring JNICALL Java_com_tecsec_OpenVEIL_Token_getEnterpriseId
(JNIEnv *env, jobject thisObj)
{
	// Get a reference to this object's class
	jclass thisClass = env->GetObjectClass(thisObj);

	Token* This = getHandle<Token>(env, thisObj);

	if (This == nullptr)
		return nullptr;
	return tsAsciiToJstring(env, This->enterpriseId());
}

/*
* Class:     com_tecsec_OpenVEIL_Token
* Method:    getMemberId
* Signature: ()Ljava/lang/String;
*/
JNIEXPORT jstring JNICALL Java_com_tecsec_OpenVEIL_Token_getMemberId
(JNIEnv *env, jobject thisObj)
{
	// Get a reference to this object's class
	jclass thisClass = env->GetObjectClass(thisObj);

	Token* This = getHandle<Token>(env, thisObj);

	if (This == nullptr)
		return nullptr;
	return tsAsciiToJstring(env, This->memberId());
}

/*
* Class:     com_tecsec_OpenVEIL_Token
* Method:    openSession
* Signature: ()Lcom/tecsec/OpenVEIL/Session;
*/
JNIEXPORT jobject JNICALL Java_com_tecsec_OpenVEIL_Token_openSession
(JNIEnv *env, jobject thisObj)
{
	// Get a reference to this object's class
	jclass thisClass = env->GetObjectClass(thisObj);

	Token* This = getHandle<Token>(env, thisObj);

	if (This == nullptr)
		return nullptr;

	jclass cls = env->FindClass("com/tecsec/OpenVEIL/Session");
	jmethodID constructor = env->GetMethodID(cls, "<init>", "()V");
	jobject object = env->NewObject(cls, constructor);
	setHandle(env, object, This->openSession());
	return object;
}

/*
* Class:     com_tecsec_OpenVEIL_Token
* Method:    initialize
* Signature: ()V
*/
JNIEXPORT void JNICALL Java_com_tecsec_OpenVEIL_Token_initialize
(JNIEnv *env, jobject thisObj)
{
	setHandle(env, thisObj, new Token());
}

/*
* Class:     com_tecsec_OpenVEIL_Token
* Method:    terminate
* Signature: ()V
*/
JNIEXPORT void JNICALL Java_com_tecsec_OpenVEIL_Token_terminate
(JNIEnv *env, jobject thisObj)
{
	Token* This = getHandle<Token>(env, thisObj);

	if (This != nullptr)
	{
		delete This;
		This = nullptr;
		setHandle(env, thisObj, This);
	}
}

