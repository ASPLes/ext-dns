/* 
 *  ext-dns: a DNS framework
 *  Copyright (C) 2012 Advanced Software Production Line, S.L.
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public License
 *  as published by the Free Software Foundation; either version 2.1
 *  of the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this program; if not, write to the Free
 *  Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
 *  02111-1307 USA
 *  
 *  You may find a copy of the license under this software is released
 *  at COPYING file. This is LGPL software: you are welcome to develop
 *  proprietary applications using this library without any royalty or
 *  fee but returning back any change, improvement or addition in the
 *  form of source code, project image, documentation patches, etc.
 *
 *  For commercial support contact us:
 *          
 *      Postal address:
 *         Advanced Software Production Line, S.L.
 *         C/ Antonio Suarez Nº 10, 
 *         Edificio Alius A, Despacho 102
 *         Alcalá de Henares 28802 (Madrid)
 *         Spain
 *
 *      Email address:
 *         info@aspl.es - http://www.aspl.es/ext-dns
 */
#include <ext-dns.h>
#include <ext-dns-private.h>

/**
 * @brief Allows to get the integer value stored in the provided
 * environment varible.
 *
 * The function tries to get the content from the environment
 * variable, and return the integer content that it is
 * representing. The function asumes the environment variable provides
 * has a numeric value. 
 * 
 * @return The variable numeric value. If the variable is not defined,
 * then 0 will be returned.
 */
int      ext_dns_support_getenv_int                 (const char * env_name)
{
#if defined (AXL_OS_UNIX)
	/* get the variable value */
	char * variable = getenv (env_name);

	if (variable == NULL)
		return 0;
	
	/* just return the content translated */
	return (strtol (variable, NULL, 10));
#elif defined(AXL_OS_WIN32)
	char  variable[1024];
	int   size_returned = 0;
	int   value         = 0;

	/* get the content of the variable */
	memset (variable, 0, sizeof (char) * 1024);
	size_returned = GetEnvironmentVariable (env_name, variable, 1023);

	if (size_returned > 1023) {
		return 0;
	}
	
	/* return the content translated */
	value = (strtol (variable, NULL, 10));

	return value;
#endif	
}

/** 
 * @brief Allows to get the string variable found at the provided
 * env_name.
 *
 * The function tries to get the content from the environment
 * variable, and return the string content that it is
 * representing. 
 * 
 * @return The variable value or NULL if it fails. The caller must
 * dealloc the string returned when no longer needed by calling to
 * axl_free.
 */
char *   ext_dns_support_getenv                 (const char * env_name)
{
#if defined (AXL_OS_UNIX)
	/* get the variable value */
	char * variable = getenv (env_name);

	if (variable == NULL)
		return NULL;
	
	/* just return the content translated */
	return axl_strdup (variable);

#elif defined(AXL_OS_WIN32)

	char  variable[1024];
	int   size_returned = 0;

	/* get the content of the variable */
	memset (variable, 0, sizeof (char) * 1024);
	size_returned = GetEnvironmentVariable (env_name, variable, 1023);

	if (size_returned > 1023) {
		return 0;
	}
	
	/* return the content translated */
	return axl_strdup (variable);
#endif	
}

/**
 * @brief Allows to configure the environment value identified by
 * env_name, with the value provided env_value.
 *
 * @param env_name The environment variable to configure.
 *
 * @param env_value The environment value to configure. The value
 * provide must be not NULL. To unset an environment variable use \ref ext_dns_support_unsetenv
 *
 * @return axl_true if the operation was successfully completed, otherwise
 * axl_false is returned.
 */
axl_bool     ext_dns_support_setenv                     (const char * env_name, 
							const char * env_value)
{
	/* check values received */
	if (env_name == NULL || env_value == NULL)
		return axl_false;
	
#if defined (AXL_OS_WIN32)
	/* use windows implementation */
	return SetEnvironmentVariable (env_name, env_value);
#elif defined(AXL_OS_UNIX)
	/* use the unix implementation */
	return setenv (env_name, env_value, 1) == 0;
#endif
}

/**
 * @brief Allows to unset the provided environment variable.
 *
 * @param env_name The environment variable to unset its value.
 *
 * @return axl_true if the operation was successfully completed, otherwise
 * axl_false is returned.
 */
axl_bool      ext_dns_support_unsetenv                   (const char * env_name)
{
	/* check values received */
	if (env_name == NULL)
		return axl_false;

#if defined (AXL_OS_WIN32)
	/* use windows implementation */
	return SetEnvironmentVariable (env_name, NULL);
#elif defined(AXL_OS_UNIX)
	/* use the unix implementation */
	setenv (env_name, "", 1);
		
	/* always axl_true */
	return axl_true;
#endif
}

/** 
 * @brief Allows to convert the provided integer value into its string
 * representation leaving the result on the provided buffer.
 *
 * @param value The value to convert.
 * @param buffer Pointer to the buffer that will hold the result.
 * @param buffer_size The size of the buffer that will hold the result.
 *
 * Note the function does not place a NUL char at the end of the number
 * written.
 * 
 * @return The function returns bytes written into the buffer or -1 if
 * the buffer can't hold the content.
 */ 
int      ext_dns_support_itoa                       (unsigned int    value,
						    char          * buffer,
						    int             buffer_size)
{
	static char digits[] = "0123456789";
	char        inverse[10];
	int         iterator  = 0;
	int         iterator2 = 0;

	if (buffer_size <= 0)
		return -1;

	/* do the conversion */
	while (iterator < 10) {
		/* copy content */
		inverse[iterator] = digits[value % 10];

		/* reduce the value */
		value = value / 10;

		if (value == 0)
			break;
		iterator++;
	} /* end while */

	/* now reserve the content */
	while (iterator2 < buffer_size) {
		buffer[iterator2] = inverse[iterator];
		iterator2++;
		iterator--;

		if (iterator == -1)
			break;
			
	} /* end while */
    
	/* check result */
	if (iterator != -1) 
		return -1;

	/* return size created */
	return iterator2;
}

/**
 * @brief Thread safe implementation for inet_ntoa.
 *
 * @param ctx The ext_dns context where the operation will be
 * performed.  @param sin Socket information where to get inet_ntoa
 * result.
 *
 * @return A newly allocated string that must be deallocated with
 * axl_free that contains the host information. The function return
 * NULL if it fails.
 */
char   * ext_dns_support_inet_ntoa                  (extDnsCtx           * ctx, 
						    struct sockaddr_in  * sin)
{
	char * result;

	v_return_val_if_fail (ctx && sin, NULL);

	/* lock during operation */
	ext_dns_mutex_lock (&ctx->inet_ntoa_mutex);

	/* allocate the string */
	result = axl_strdup (inet_ntoa (sin->sin_addr));

	/* unlock */
	ext_dns_mutex_unlock (&ctx->inet_ntoa_mutex);

	/* return the string */
	return result;
}

