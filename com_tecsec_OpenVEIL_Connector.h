/* DO NOT EDIT THIS FILE - it is machine generated */
#include <jni.h>
/* Header for class com_tecsec_OpenVEIL_Connector */

#ifndef _Included_com_tecsec_OpenVEIL_Connector
#define _Included_com_tecsec_OpenVEIL_Connector
#ifdef __cplusplus
extern "C" {
#endif
/*
 * Class:     com_tecsec_OpenVEIL_Connector
 * Method:    genericConnectToServer
 * Signature: (Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)I
 */
JNIEXPORT jint JNICALL Java_com_tecsec_OpenVEIL_Connector_genericConnectToServer
  (JNIEnv *, jobject, jstring, jstring, jstring);

/*
 * Class:     com_tecsec_OpenVEIL_Connector
 * Method:    connectToServer
 * Signature: (Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)I
 */
JNIEXPORT jint JNICALL Java_com_tecsec_OpenVEIL_Connector_connectToServer
  (JNIEnv *, jobject, jstring, jstring, jstring);

/*
 * Class:     com_tecsec_OpenVEIL_Connector
 * Method:    disconnect
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_com_tecsec_OpenVEIL_Connector_disconnect
  (JNIEnv *, jobject);

/*
 * Class:     com_tecsec_OpenVEIL_Connector
 * Method:    isConnected
 * Signature: ()Z
 */
JNIEXPORT jboolean JNICALL Java_com_tecsec_OpenVEIL_Connector_isConnected
  (JNIEnv *, jobject);

/*
 * Class:     com_tecsec_OpenVEIL_Connector
 * Method:    sendJsonRequest
 * Signature: (Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lcom/tecsec/OpenVEIL/RequestResults;)Z
 */
JNIEXPORT jboolean JNICALL Java_com_tecsec_OpenVEIL_Connector_sendJsonRequest
  (JNIEnv *, jobject, jstring, jstring, jstring, jobject);

/*
 * Class:     com_tecsec_OpenVEIL_Connector
 * Method:    sendBase64Request
 * Signature: (Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lcom/tecsec/OpenVEIL/RequestResults;)Z
 */
JNIEXPORT jboolean JNICALL Java_com_tecsec_OpenVEIL_Connector_sendBase64Request
  (JNIEnv *, jobject, jstring, jstring, jstring, jobject);

#ifdef __cplusplus
}
#endif
#endif