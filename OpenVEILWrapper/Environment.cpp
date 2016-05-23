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
#include "Environment.h"
#include "VEIL.h"
#include "handle.h"

JavaVM *cached_jvm;                                   // A pointer to the VM from which
													  //we can get the JNIEnv for doing callbacks:

Environment::Environment()
{

}
Environment::~Environment()
{

}
void Environment::DispatchEvents() // Call this in the main thread to receive queued up events
{
	// TODO:  Implement me
}
bool Environment::InitializeVEIL(bool initiateChangeMonitoring)
{
	// Forces the core system to initialize
	if (!::ServiceLocator())
		return false;

	if (initiateChangeMonitoring)
	{

	}
	return true;
}
bool Environment::TerminateVEIL()
{
	TerminateVEILSystem();
	return true;
}
/******************************************************************************
JNI_OnLoad will be called when the jvm loads this library
******************************************************************************/
JNIEXPORT jint JNICALL
JNI_OnLoad(JavaVM *jvm, void *reserved)
{
	JNIEnv *env;
	cached_jvm = jvm;  /* cache the JavaVM pointer */

	if (jvm->GetEnv((void **)&env, JNI_VERSION_1_6)) {
		printf("JNI version is not supported");
		return JNI_ERR; /* JNI version not supported */
	}
	return JNI_VERSION_1_6;
}


/*
* Class:     com_tecsec_OpenVEIL_Environment
* Method:    DispatchEvents
* Signature: ()V
*/
JNIEXPORT void JNICALL Java_com_tecsec_OpenVEIL_Environment_DispatchEvents(JNIEnv *env, jobject thisObj)
{
	// Get a reference to this object's class
	jclass thisClass = env->GetObjectClass(thisObj);

	Environment* This = getHandle<Environment>(env, thisObj);

	if (This == nullptr)
		return;
	This->DispatchEvents();
}

/*
* Class:     com_tecsec_OpenVEIL_Environment
* Method:    InitializeVEIL
* Signature: (Z)Z
*/
JNIEXPORT jboolean JNICALL Java_com_tecsec_OpenVEIL_Environment_InitializeVEIL(JNIEnv *env, jobject thisObj, jboolean initiateChangeMonitoring)
{
	// Get a reference to this object's class
	jclass thisClass = env->GetObjectClass(thisObj);

	Environment* This = getHandle<Environment>(env, thisObj);

	if (This == nullptr)
		return JNI_FALSE;
	return This->InitializeVEIL(initiateChangeMonitoring) ? JNI_TRUE : JNI_FALSE;
}

/*
* Class:     com_tecsec_OpenVEIL_Environment
* Method:    TerminateVEIL
* Signature: ()Z
*/
JNIEXPORT jboolean JNICALL Java_com_tecsec_OpenVEIL_Environment_TerminateVEIL(JNIEnv *env, jobject thisObj)
{
	// Get a reference to this object's class
	jclass thisClass = env->GetObjectClass(thisObj);

	Environment* This = getHandle<Environment>(env, thisObj);

	if (This == nullptr)
		return JNI_FALSE;
	return This->TerminateVEIL() ? JNI_TRUE : JNI_FALSE;
}

/*
* Class:     com_tecsec_OpenVEIL_Environment
* Method:    initialize
* Signature: ()V
*/
JNIEXPORT void JNICALL Java_com_tecsec_OpenVEIL_Environment_initialize(JNIEnv *env, jobject thisObj)
{
	setHandle(env, thisObj, new Environment());
}

/*
* Class:     com_tecsec_OpenVEIL_Environment
* Method:    terminate
* Signature: ()V
*/
JNIEXPORT void JNICALL Java_com_tecsec_OpenVEIL_Environment_terminate(JNIEnv *env, jobject thisObj)
{
	Environment* This = getHandle<Environment>(env, thisObj);

	if (This != nullptr)
	{
		delete This;
		This = nullptr;
		setHandle(env, thisObj, This);
	}
}

void ThrowJNIException(const char* pzFile, int iLine, const char* pzMessage)
{
	char g_azErrorMessage[500];

	//Creating the error messages
	if (pzFile != NULL && pzMessage != NULL && iLine != 0)
		sprintf(g_azErrorMessage, "JNIException ! \n \
      File \t\t:  %s \n \
      Line number \t\t: %d \n \
      Reason for Exception\t: %s ", pzFile, iLine, pzMessage);
	jclass    tClass = NULL;
	JNIEnv *env;

	//Get the JNIEnv by attaching to the current thread.
	cached_jvm->AttachCurrentThread((void **)&env, NULL);
	//Check for null. If something went wrong, give up
	if (env == NULL) {
		printf("Invalid null pointer in ThrowJNIException ");
		return;
	}
	//Find the exception class.
	tClass = env->FindClass("java/lang/RuntimeException");
	if (tClass == NULL) {
		printf("Not found %s", "java/lang/RuntimeException");
		return;
	}
	//Throw the exception with error info
	env->ThrowNew(tClass, g_azErrorMessage);
	env->DeleteLocalRef(tClass);
}
