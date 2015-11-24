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


#ifndef __HANDLE_H__
#define __HANDLE_H__

/*
Type Signature					  Java Type
	Z								boolean
	B								byte
	C								char
	S								short
	I								int
	J								long
	F								float
	D								double
	L fully-qualified-class ;		fully-qualified-class
	[ type							type[]
	( arg-types ) ret-type			method type

For example, the Java method:

	long f (int n, String s, int[] arr);

has the following type signature:

	(ILjava/lang/String;[I)J

*/
inline jfieldID getField(JNIEnv *env, jobject obj, const char* name, const char* type)
{
	jclass c = env->GetObjectClass(obj);
	// J is the type signature for long:
	return env->GetFieldID(c, name, type);
}


inline jfieldID getHandleField(JNIEnv *env, jobject obj)
{
	return getField(env, obj, "handle", "J");
}

template <typename T>
T *getHandle(JNIEnv *env, jobject obj)
{
	jlong handle = env->GetLongField(obj, getHandleField(env, obj));
	return reinterpret_cast<T *>(handle);
}

template <typename T>
void setHandle(JNIEnv *env, jobject obj, T *t)
{
	jlong handle = reinterpret_cast<jlong>(t);
	env->SetLongField(obj, getHandleField(env, obj), handle);
}

inline jboolean getBool(JNIEnv *env, jobject obj, const char* name)
{
	return env->GetBooleanField(obj, getField(env, obj, name, "Z"));
}
inline void setBool(JNIEnv *env, jobject obj, const char* name, jboolean setTo)
{
	env->SetBooleanField(obj, getField(env, obj, name, "Z"), setTo);
}
inline jint getInt(JNIEnv *env, jobject obj, const char* name)
{
	return env->GetIntField(obj, getField(env, obj, name, "I"));
}
inline void setInt(JNIEnv *env, jobject obj, const char* name, jint setTo)
{
	env->SetIntField(obj, getField(env, obj, name, "I"), setTo);
}
inline jlong getLong(JNIEnv *env, jobject obj, const char* name)
{
	return env->GetLongField(obj, getField(env, obj, name, "J"));
}
inline void setLong(JNIEnv *env, jobject obj, const char* name, jlong setTo)
{
	env->SetLongField(obj, getField(env, obj, name, "J"), setTo);
}
inline jstring getString(JNIEnv *env, jobject obj, const char* name)
{
	return (jstring)env->GetObjectField(obj, getField(env, obj, name, "Ljava/lang/String;"));
}
inline void setString(JNIEnv *env, jobject obj, const char* name, const tsAscii& setTo)
{
	jstring val = env->NewStringUTF(setTo.c_str());
	if (val != nullptr)
		env->SetObjectField(obj, getField(env, obj, name, "Ljava/lang/String;"), val);
}

#endif // __HANDLE_H__
