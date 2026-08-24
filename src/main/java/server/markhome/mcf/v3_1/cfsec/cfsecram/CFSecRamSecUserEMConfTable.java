
// Description: Java 25 in-memory RAM DbIO implementation for SecUserEMConf.

/*
 *	server.markhome.mcf.CFSec
 *
 *	Copyright (c) 2016-2026 Mark Stephen Sobkow
 *	
 *	Mark's Code Fractal 3.1 CFSec - Security Services
 *	
 *	Copyright (c) 2016-2026 Mark Stephen Sobkow mark.sobkow@gmail.com
 *	
 *	These files are part of Mark's Code Fractal CFSec.
 *	
 *	Licensed under the Apache License, Version 2.0 (the "License");
 *	you may not use this file except in compliance with the License.
 *	You may obtain a copy of the License at
 *	
 *	http://www.apache.org/licenses/LICENSE-2.0
 *	
 *	Unless required by applicable law or agreed to in writing, software
 *	distributed under the License is distributed on an "AS IS" BASIS,
 *	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *	See the License for the specific language governing permissions and
 *	limitations under the License.
 *	
 */

package server.markhome.mcf.v3_1.cfsec.cfsecram;

import java.math.*;
import java.sql.*;
import java.text.*;
import java.time.*;
import java.util.*;
import org.apache.commons.codec.binary.Base64;
import server.markhome.mcf.v3_1.cflib.*;
import server.markhome.mcf.v3_1.cflib.dbutil.*;
import server.markhome.mcf.v3_1.cflib.keyhash.*;

import server.markhome.mcf.v3_1.cfsec.cfsec.*;
import server.markhome.mcf.v3_1.cfsec.cfsec.buff.*;
import server.markhome.mcf.v3_1.cfsec.cfsecobj.*;

/*
 *	CFSecRamSecUserEMConfTable in-memory RAM DbIO implementation
 *	for SecUserEMConf.
 */
public class CFSecRamSecUserEMConfTable
	implements ICFSecSecUserEMConfTable
{
	private ICFSecSchema schema;
	private Map< $iterate Columns ( lone implIJavaOptAtomType first implIJavaOptAtomType each implCommaIJavaOptAtomType empty empty )$,
				CFSecBuffSecUserEMConf > dictByPKey
		= new HashMap< $iterate Columns ( lone implIJavaOptAtomType first implIJavaOptAtomType each implCommaIJavaOptAtomType empty empty )$,
				CFSecBuffSecUserEMConf >();
	private Map< CFSecBuffSecUserEMConfByUUuid6IdxKey,
			CFSecBuffSecUserEMConf > dictByUUuid6Idx
		= new HashMap< CFSecBuffSecUserEMConfByUUuid6IdxKey,
			CFSecBuffSecUserEMConf >();
	private Map< CFSecBuffSecUserEMConfByConfEMAddrIdxKey,
				Map< $iterate Columns ( lone implIJavaOptAtomType first implIJavaOptAtomType each implCommaIJavaOptAtomType empty empty )$,
					CFSecBuffSecUserEMConf >> dictByConfEMAddrIdx
		= new HashMap< CFSecBuffSecUserEMConfByConfEMAddrIdxKey,
				Map< $iterate Columns ( lone implIJavaOptAtomType first implIJavaOptAtomType each implCommaIJavaOptAtomType empty empty )$,
					CFSecBuffSecUserEMConf >>();
	private Map< CFSecBuffSecUserEMConfBySentStampIdxKey,
				Map< $iterate Columns ( lone implIJavaOptAtomType first implIJavaOptAtomType each implCommaIJavaOptAtomType empty empty )$,
					CFSecBuffSecUserEMConf >> dictBySentStampIdx
		= new HashMap< CFSecBuffSecUserEMConfBySentStampIdxKey,
				Map< $iterate Columns ( lone implIJavaOptAtomType first implIJavaOptAtomType each implCommaIJavaOptAtomType empty empty )$,
					CFSecBuffSecUserEMConf >>();
	private Map< CFSecBuffSecUserEMConfByNewAcctIdxKey,
				Map< $iterate Columns ( lone implIJavaOptAtomType first implIJavaOptAtomType each implCommaIJavaOptAtomType empty empty )$,
					CFSecBuffSecUserEMConf >> dictByNewAcctIdx
		= new HashMap< CFSecBuffSecUserEMConfByNewAcctIdxKey,
				Map< $iterate Columns ( lone implIJavaOptAtomType first implIJavaOptAtomType each implCommaIJavaOptAtomType empty empty )$,
					CFSecBuffSecUserEMConf >>();

	public CFSecRamSecUserEMConfTable( ICFSecSchema argSchema ) {
		schema = argSchema;
	}

	public CFSecBuffSecUserEMConf ensureRec(ICFSecSecUserEMConf rec) {
		return (((CFSecBuffSecUserEMConfFactoryService)(schema.getCFSecBuffFactory().getFactorySecUserEMConf())).ensureRec(rec));
	}

	@Override
	public ICFSecSecUserEMConf createSecUserEMConf( ICFSecAuthorization Authorization,
		ICFSecSecUserEMConf iBuff )
	{
		final String S_ProcName = "createSecUserEMConf";
		
		CFSecBuffSecUserEMConf Buff = (CFSecBuffSecUserEMConf)ensureRec(iBuff);
		$iterate Columns ( lone implIJavaOptAtomType first implIJavaOptAtomType each implCommaIJavaOptAtomType empty empty )$ pkey;
		pkey = Buff.getRequiredSecUserId();
		pkey = Buff.getRequiredSecUserId();
		Buff.setRequiredContainerUser( pkey );
		Buff.setRequiredSecUserId( pkey );
		CFSecBuffSecUserEMConfByUUuid6IdxKey keyUUuid6Idx = (CFSecBuffSecUserEMConfByUUuid6IdxKey)schema.getCFSecBuffFactory().getFactorySecUserEMConf().newByUUuid6IdxKey();
		keyUUuid6Idx.setRequiredEMConfirmationUuid6( Buff.getRequiredEMConfirmationUuid6() );

		CFSecBuffSecUserEMConfByConfEMAddrIdxKey keyConfEMAddrIdx = (CFSecBuffSecUserEMConfByConfEMAddrIdxKey)schema.getCFSecBuffFactory().getFactorySecUserEMConf().newByConfEMAddrIdxKey();
		keyConfEMAddrIdx.setRequiredConfirmEMailAddr( Buff.getRequiredConfirmEMailAddr() );

		CFSecBuffSecUserEMConfBySentStampIdxKey keySentStampIdx = (CFSecBuffSecUserEMConfBySentStampIdxKey)schema.getCFSecBuffFactory().getFactorySecUserEMConf().newBySentStampIdxKey();
		keySentStampIdx.setRequiredEMailSentStamp( Buff.getRequiredEMailSentStamp() );

		CFSecBuffSecUserEMConfByNewAcctIdxKey keyNewAcctIdx = (CFSecBuffSecUserEMConfByNewAcctIdxKey)schema.getCFSecBuffFactory().getFactorySecUserEMConf().newByNewAcctIdxKey();
		keyNewAcctIdx.setRequiredNewAccount( Buff.getRequiredNewAccount() );

		// Validate unique indexes

		if( dictByPKey.containsKey( pkey ) ) {
			throw new CFLibPrimaryKeyNotNewException( getClass(), S_ProcName, pkey );
		}

		if( dictByUUuid6Idx.containsKey( keyUUuid6Idx ) ) {
			throw new CFLibUniqueIndexViolationException( getClass(),
				S_ProcName,
				"SecUserEMConfUuid6Idx",
				"SecUserEMConfUuid6Idx",
				keyUUuid6Idx );
		}

		// Validate foreign keys

		{
			boolean allNull = true;
			allNull = false;
			if( ! allNull ) {
				if( null == schema.getTableSecUser().readDerivedByIdIdx( Authorization,
						Buff.getRequiredSecUserId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						S_ProcName,
						"Container",
						"Container",
						"SecUser",
						"SecUser",
						"SecUser",
						"SecUser",
						null );
				}
			}
		}

		// Proceed with adding the new record

		dictByPKey.put( pkey, Buff );

		dictByUUuid6Idx.put( keyUUuid6Idx, Buff );

		Map< $iterate Columns ( lone implIJavaOptAtomType first implIJavaOptAtomType each implCommaIJavaOptAtomType empty empty )$, CFSecBuffSecUserEMConf > subdictConfEMAddrIdx;
		if( dictByConfEMAddrIdx.containsKey( keyConfEMAddrIdx ) ) {
			subdictConfEMAddrIdx = dictByConfEMAddrIdx.get( keyConfEMAddrIdx );
		}
		else {
			subdictConfEMAddrIdx = new HashMap< $iterate Columns ( lone implIJavaOptAtomType first implIJavaOptAtomType each implCommaIJavaOptAtomType empty empty )$, CFSecBuffSecUserEMConf >();
			dictByConfEMAddrIdx.put( keyConfEMAddrIdx, subdictConfEMAddrIdx );
		}
		subdictConfEMAddrIdx.put( pkey, Buff );

		Map< $iterate Columns ( lone implIJavaOptAtomType first implIJavaOptAtomType each implCommaIJavaOptAtomType empty empty )$, CFSecBuffSecUserEMConf > subdictSentStampIdx;
		if( dictBySentStampIdx.containsKey( keySentStampIdx ) ) {
			subdictSentStampIdx = dictBySentStampIdx.get( keySentStampIdx );
		}
		else {
			subdictSentStampIdx = new HashMap< $iterate Columns ( lone implIJavaOptAtomType first implIJavaOptAtomType each implCommaIJavaOptAtomType empty empty )$, CFSecBuffSecUserEMConf >();
			dictBySentStampIdx.put( keySentStampIdx, subdictSentStampIdx );
		}
		subdictSentStampIdx.put( pkey, Buff );

		Map< $iterate Columns ( lone implIJavaOptAtomType first implIJavaOptAtomType each implCommaIJavaOptAtomType empty empty )$, CFSecBuffSecUserEMConf > subdictNewAcctIdx;
		if( dictByNewAcctIdx.containsKey( keyNewAcctIdx ) ) {
			subdictNewAcctIdx = dictByNewAcctIdx.get( keyNewAcctIdx );
		}
		else {
			subdictNewAcctIdx = new HashMap< $iterate Columns ( lone implIJavaOptAtomType first implIJavaOptAtomType each implCommaIJavaOptAtomType empty empty )$, CFSecBuffSecUserEMConf >();
			dictByNewAcctIdx.put( keyNewAcctIdx, subdictNewAcctIdx );
		}
		subdictNewAcctIdx.put( pkey, Buff );

		if (Buff == null) {
			return( null );
		}
		else {
			int classCode = Buff.getClassCode();
			if (classCode == ICFSecSecUserEMConf.CLASS_CODE) {
				CFSecBuffSecUserEMConf retbuff = ((CFSecBuffSecUserEMConf)(schema.getCFSecBuffFactory().getFactorySecUserEMConf().newRec()));
				retbuff.set(Buff);
				return( retbuff );
			}
			else {
				throw new CFLibUnsupportedClassException(getClass(), S_ProcName, "-create-buff-cloning-", (Integer)classCode, "Classcode not recognized: " + Integer.toString(classCode));
			}
		}
	}

	@Override
	public ICFSecSecUserEMConf readDerived( ICFSecAuthorization Authorization,
		$iterate Columns ( lone implIJavaOptAtomType first implIJavaOptAtomType each implCommaIJavaOptAtomType empty empty )$ PKey )
	{
		final String S_ProcName = "CFSecRamSecUserEMConf.readDerived";
		ICFSecSecUserEMConf buff;
		if( PKey == null ) {
			return( null );
		}
		if( dictByPKey.containsKey( PKey ) ) {
			buff = dictByPKey.get( PKey );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecUserEMConf lockDerived( ICFSecAuthorization Authorization,
		$iterate Columns ( lone implIJavaOptAtomType first implIJavaOptAtomType each implCommaIJavaOptAtomType empty empty )$ PKey )
	{
		final String S_ProcName = "CFSecRamSecUserEMConf.lockDerived";
		ICFSecSecUserEMConf buff;
		if( dictByPKey.containsKey( PKey ) ) {
			buff = dictByPKey.get( PKey );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecUserEMConf[] readAllDerived( ICFSecAuthorization Authorization ) {
		final String S_ProcName = "CFSecRamSecUserEMConf.readAllDerived";
		ICFSecSecUserEMConf[] retList = new ICFSecSecUserEMConf[ dictByPKey.values().size() ];
		Iterator< CFSecBuffSecUserEMConf > iter = dictByPKey.values().iterator();
		int idx = 0;
		while( iter.hasNext() ) {
			retList[ idx++ ] = iter.next();
		}
		return( retList );
	}

	@Override
	public ICFSecSecUserEMConf readDerivedByUUuid6Idx( ICFSecAuthorization Authorization,
		$implIJavaAtomType$ EMConfirmationUuid6 )
	{
		final String S_ProcName = "CFSecRamSecUserEMConf.readDerivedByUUuid6Idx";
		CFSecBuffSecUserEMConfByUUuid6IdxKey key = (CFSecBuffSecUserEMConfByUUuid6IdxKey)schema.getCFSecBuffFactory().getFactorySecUserEMConf().newByUUuid6IdxKey();

		key.setRequiredEMConfirmationUuid6( EMConfirmationUuid6 );
		ICFSecSecUserEMConf buff;
		if( dictByUUuid6Idx.containsKey( key ) ) {
			buff = dictByUUuid6Idx.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecUserEMConf[] readDerivedByConfEMAddrIdx( ICFSecAuthorization Authorization,
		$implIJavaAtomType$ ConfirmEMailAddr )
	{
		final String S_ProcName = "CFSecRamSecUserEMConf.readDerivedByConfEMAddrIdx";
		CFSecBuffSecUserEMConfByConfEMAddrIdxKey key = (CFSecBuffSecUserEMConfByConfEMAddrIdxKey)schema.getCFSecBuffFactory().getFactorySecUserEMConf().newByConfEMAddrIdxKey();

		key.setRequiredConfirmEMailAddr( ConfirmEMailAddr );
		ICFSecSecUserEMConf[] recArray;
		if( dictByConfEMAddrIdx.containsKey( key ) ) {
			Map< $iterate Columns ( lone implIJavaOptAtomType first implIJavaOptAtomType each implCommaIJavaOptAtomType empty empty )$, CFSecBuffSecUserEMConf > subdictConfEMAddrIdx
				= dictByConfEMAddrIdx.get( key );
			recArray = new ICFSecSecUserEMConf[ subdictConfEMAddrIdx.size() ];
			Iterator< CFSecBuffSecUserEMConf > iter = subdictConfEMAddrIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< $iterate Columns ( lone implIJavaOptAtomType first implIJavaOptAtomType each implCommaIJavaOptAtomType empty empty )$, CFSecBuffSecUserEMConf > subdictConfEMAddrIdx
				= new HashMap< $iterate Columns ( lone implIJavaOptAtomType first implIJavaOptAtomType each implCommaIJavaOptAtomType empty empty )$, CFSecBuffSecUserEMConf >();
			dictByConfEMAddrIdx.put( key, subdictConfEMAddrIdx );
			recArray = new ICFSecSecUserEMConf[0];
		}
		return( recArray );
	}

	@Override
	public ICFSecSecUserEMConf[] readDerivedBySentStampIdx( ICFSecAuthorization Authorization,
		$implIJavaAtomType$ EMailSentStamp )
	{
		final String S_ProcName = "CFSecRamSecUserEMConf.readDerivedBySentStampIdx";
		CFSecBuffSecUserEMConfBySentStampIdxKey key = (CFSecBuffSecUserEMConfBySentStampIdxKey)schema.getCFSecBuffFactory().getFactorySecUserEMConf().newBySentStampIdxKey();

		key.setRequiredEMailSentStamp( EMailSentStamp );
		ICFSecSecUserEMConf[] recArray;
		if( dictBySentStampIdx.containsKey( key ) ) {
			Map< $iterate Columns ( lone implIJavaOptAtomType first implIJavaOptAtomType each implCommaIJavaOptAtomType empty empty )$, CFSecBuffSecUserEMConf > subdictSentStampIdx
				= dictBySentStampIdx.get( key );
			recArray = new ICFSecSecUserEMConf[ subdictSentStampIdx.size() ];
			Iterator< CFSecBuffSecUserEMConf > iter = subdictSentStampIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< $iterate Columns ( lone implIJavaOptAtomType first implIJavaOptAtomType each implCommaIJavaOptAtomType empty empty )$, CFSecBuffSecUserEMConf > subdictSentStampIdx
				= new HashMap< $iterate Columns ( lone implIJavaOptAtomType first implIJavaOptAtomType each implCommaIJavaOptAtomType empty empty )$, CFSecBuffSecUserEMConf >();
			dictBySentStampIdx.put( key, subdictSentStampIdx );
			recArray = new ICFSecSecUserEMConf[0];
		}
		return( recArray );
	}

	@Override
	public ICFSecSecUserEMConf[] readDerivedByNewAcctIdx( ICFSecAuthorization Authorization,
		$implIJavaAtomType$ NewAccount )
	{
		final String S_ProcName = "CFSecRamSecUserEMConf.readDerivedByNewAcctIdx";
		CFSecBuffSecUserEMConfByNewAcctIdxKey key = (CFSecBuffSecUserEMConfByNewAcctIdxKey)schema.getCFSecBuffFactory().getFactorySecUserEMConf().newByNewAcctIdxKey();

		key.setRequiredNewAccount( NewAccount );
		ICFSecSecUserEMConf[] recArray;
		if( dictByNewAcctIdx.containsKey( key ) ) {
			Map< $iterate Columns ( lone implIJavaOptAtomType first implIJavaOptAtomType each implCommaIJavaOptAtomType empty empty )$, CFSecBuffSecUserEMConf > subdictNewAcctIdx
				= dictByNewAcctIdx.get( key );
			recArray = new ICFSecSecUserEMConf[ subdictNewAcctIdx.size() ];
			Iterator< CFSecBuffSecUserEMConf > iter = subdictNewAcctIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< $iterate Columns ( lone implIJavaOptAtomType first implIJavaOptAtomType each implCommaIJavaOptAtomType empty empty )$, CFSecBuffSecUserEMConf > subdictNewAcctIdx
				= new HashMap< $iterate Columns ( lone implIJavaOptAtomType first implIJavaOptAtomType each implCommaIJavaOptAtomType empty empty )$, CFSecBuffSecUserEMConf >();
			dictByNewAcctIdx.put( key, subdictNewAcctIdx );
			recArray = new ICFSecSecUserEMConf[0];
		}
		return( recArray );
	}

	@Override
	public ICFSecSecUserEMConf readDerivedByIdIdx( ICFSecAuthorization Authorization,
		$implIJavaAtomType$ SecUserId )
	{
		final String S_ProcName = "CFSecRamSecUserEMConf.readDerivedByIdIdx() ";
		ICFSecSecUserEMConf buff;
		if( dictByPKey.containsKey( SecUserId ) ) {
			buff = dictByPKey.get( SecUserId );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecUserEMConf readRec( ICFSecAuthorization Authorization,
		$iterate Columns ( lone implIJavaOptAtomType first implIJavaOptAtomType each implCommaIJavaOptAtomType empty empty )$ PKey )
	{
		final String S_ProcName = "CFSecRamSecUserEMConf.readRec";
		ICFSecSecUserEMConf buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecSecUserEMConf.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecUserEMConf lockRec( ICFSecAuthorization Authorization,
		$iterate Columns ( lone implIJavaOptAtomType first implIJavaOptAtomType each implCommaIJavaOptAtomType empty empty )$ PKey )
	{
		final String S_ProcName = "lockRec";
		ICFSecSecUserEMConf buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecSecUserEMConf.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecUserEMConf[] readAllRec( ICFSecAuthorization Authorization )
	{
		final String S_ProcName = "CFSecRamSecUserEMConf.readAllRec";
		ICFSecSecUserEMConf buff;
		ArrayList<ICFSecSecUserEMConf> filteredList = new ArrayList<ICFSecSecUserEMConf>();
		ICFSecSecUserEMConf[] buffList = readAllDerived( Authorization );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecUserEMConf.CLASS_CODE ) ) {
				filteredList.add( buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecUserEMConf[0] ) );
	}

	/**
	 *	Read a page of all the specific SecUserEMConf buffer instances.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@return All the specific SecUserEMConf instances in the database accessible for the Authorization.
	 */
	@Override
	public ICFSecSecUserEMConf[] pageAllRec( ICFSecAuthorization Authorization,
		$implIJavaOptAtomType$ priorSecUserId )
	{
		final String S_ProcName = "pageAllRec";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	@Override
	public ICFSecSecUserEMConf readRecByIdIdx( ICFSecAuthorization Authorization,
		$implIJavaAtomType$ SecUserId )
	{
		final String S_ProcName = "CFSecRamSecUserEMConf.readRecByIdIdx() ";
		ICFSecSecUserEMConf buff = readDerivedByIdIdx( Authorization,
			SecUserId );
		if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecUserEMConf.CLASS_CODE ) ) {
			return( (ICFSecSecUserEMConf)buff );
		}
		else {
			return( null );
		}
	}

	@Override
	public ICFSecSecUserEMConf readRecByUUuid6Idx( ICFSecAuthorization Authorization,
		$implIJavaAtomType$ EMConfirmationUuid6 )
	{
		final String S_ProcName = "CFSecRamSecUserEMConf.readRecByUUuid6Idx() ";
		ICFSecSecUserEMConf buff = readDerivedByUUuid6Idx( Authorization,
			EMConfirmationUuid6 );
		if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecUserEMConf.CLASS_CODE ) ) {
			return( (ICFSecSecUserEMConf)buff );
		}
		else {
			return( null );
		}
	}

	@Override
	public ICFSecSecUserEMConf[] readRecByConfEMAddrIdx( ICFSecAuthorization Authorization,
		$implIJavaAtomType$ ConfirmEMailAddr )
	{
		final String S_ProcName = "CFSecRamSecUserEMConf.readRecByConfEMAddrIdx() ";
		ICFSecSecUserEMConf buff;
		ArrayList<ICFSecSecUserEMConf> filteredList = new ArrayList<ICFSecSecUserEMConf>();
		ICFSecSecUserEMConf[] buffList = readDerivedByConfEMAddrIdx( Authorization,
			ConfirmEMailAddr );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecUserEMConf.CLASS_CODE ) ) {
				filteredList.add( (ICFSecSecUserEMConf)buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecUserEMConf[0] ) );
	}

	@Override
	public ICFSecSecUserEMConf[] readRecBySentStampIdx( ICFSecAuthorization Authorization,
		$implIJavaAtomType$ EMailSentStamp )
	{
		final String S_ProcName = "CFSecRamSecUserEMConf.readRecBySentStampIdx() ";
		ICFSecSecUserEMConf buff;
		ArrayList<ICFSecSecUserEMConf> filteredList = new ArrayList<ICFSecSecUserEMConf>();
		ICFSecSecUserEMConf[] buffList = readDerivedBySentStampIdx( Authorization,
			EMailSentStamp );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecUserEMConf.CLASS_CODE ) ) {
				filteredList.add( (ICFSecSecUserEMConf)buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecUserEMConf[0] ) );
	}

	@Override
	public ICFSecSecUserEMConf[] readRecByNewAcctIdx( ICFSecAuthorization Authorization,
		$implIJavaAtomType$ NewAccount )
	{
		final String S_ProcName = "CFSecRamSecUserEMConf.readRecByNewAcctIdx() ";
		ICFSecSecUserEMConf buff;
		ArrayList<ICFSecSecUserEMConf> filteredList = new ArrayList<ICFSecSecUserEMConf>();
		ICFSecSecUserEMConf[] buffList = readDerivedByNewAcctIdx( Authorization,
			NewAccount );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecUserEMConf.CLASS_CODE ) ) {
				filteredList.add( (ICFSecSecUserEMConf)buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecUserEMConf[0] ) );
	}

	/**
	 *	Read a page array of the specific SecUserEMConf buffer instances identified by the duplicate key ConfEMAddrIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	ConfirmEMailAddr	The SecUserEMConf key attribute of the instance generating the id.
	 *
	 *	@return An array of derived buffer instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecSecUserEMConf[] pageRecByConfEMAddrIdx( ICFSecAuthorization Authorization,
		$implIJavaAtomType$ ConfirmEMailAddr,
		$implIJavaOptAtomType$ priorSecUserId )
	{
		final String S_ProcName = "pageRecByConfEMAddrIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	/**
	 *	Read a page array of the specific SecUserEMConf buffer instances identified by the duplicate key SentStampIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	EMailSentStamp	The SecUserEMConf key attribute of the instance generating the id.
	 *
	 *	@return An array of derived buffer instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecSecUserEMConf[] pageRecBySentStampIdx( ICFSecAuthorization Authorization,
		$implIJavaAtomType$ EMailSentStamp,
		$implIJavaOptAtomType$ priorSecUserId )
	{
		final String S_ProcName = "pageRecBySentStampIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	/**
	 *	Read a page array of the specific SecUserEMConf buffer instances identified by the duplicate key NewAcctIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	NewAccount	The SecUserEMConf key attribute of the instance generating the id.
	 *
	 *	@return An array of derived buffer instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecSecUserEMConf[] pageRecByNewAcctIdx( ICFSecAuthorization Authorization,
		$implIJavaAtomType$ NewAccount,
		$implIJavaOptAtomType$ priorSecUserId )
	{
		final String S_ProcName = "pageRecByNewAcctIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	public ICFSecSecUserEMConf updateSecUserEMConf( ICFSecAuthorization Authorization,
		ICFSecSecUserEMConf iBuff )
	{
		CFSecBuffSecUserEMConf Buff = (CFSecBuffSecUserEMConf)ensureRec(iBuff);
		$iterate Columns ( lone implIJavaOptAtomType first implIJavaOptAtomType each implCommaIJavaOptAtomType empty empty )$ pkey = ($iterate Columns ( lone implIJavaOptAtomType first implIJavaOptAtomType each implCommaIJavaOptAtomType empty empty )$)Buff.getPKey();
		CFSecBuffSecUserEMConf existing = dictByPKey.get( pkey );
		if( existing == null ) {
			throw new CFLibStaleCacheDetectedException( getClass(),
				"updateSecUserEMConf",
				"Existing record not found",
				"Existing record not found",
				"SecUserEMConf",
				"SecUserEMConf",
				pkey );
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() ) {
			throw new CFLibCollisionDetectedException( getClass(),
				"updateSecUserEMConf",
				pkey );
		}
		Buff.setRequiredRevision( Buff.getRequiredRevision() + 1 );
		CFSecBuffSecUserEMConfByUUuid6IdxKey existingKeyUUuid6Idx = (CFSecBuffSecUserEMConfByUUuid6IdxKey)schema.getCFSecBuffFactory().getFactorySecUserEMConf().newByUUuid6IdxKey();
		existingKeyUUuid6Idx.setRequiredEMConfirmationUuid6( existing.getRequiredEMConfirmationUuid6() );

		CFSecBuffSecUserEMConfByUUuid6IdxKey newKeyUUuid6Idx = (CFSecBuffSecUserEMConfByUUuid6IdxKey)schema.getCFSecBuffFactory().getFactorySecUserEMConf().newByUUuid6IdxKey();
		newKeyUUuid6Idx.setRequiredEMConfirmationUuid6( Buff.getRequiredEMConfirmationUuid6() );

		CFSecBuffSecUserEMConfByConfEMAddrIdxKey existingKeyConfEMAddrIdx = (CFSecBuffSecUserEMConfByConfEMAddrIdxKey)schema.getCFSecBuffFactory().getFactorySecUserEMConf().newByConfEMAddrIdxKey();
		existingKeyConfEMAddrIdx.setRequiredConfirmEMailAddr( existing.getRequiredConfirmEMailAddr() );

		CFSecBuffSecUserEMConfByConfEMAddrIdxKey newKeyConfEMAddrIdx = (CFSecBuffSecUserEMConfByConfEMAddrIdxKey)schema.getCFSecBuffFactory().getFactorySecUserEMConf().newByConfEMAddrIdxKey();
		newKeyConfEMAddrIdx.setRequiredConfirmEMailAddr( Buff.getRequiredConfirmEMailAddr() );

		CFSecBuffSecUserEMConfBySentStampIdxKey existingKeySentStampIdx = (CFSecBuffSecUserEMConfBySentStampIdxKey)schema.getCFSecBuffFactory().getFactorySecUserEMConf().newBySentStampIdxKey();
		existingKeySentStampIdx.setRequiredEMailSentStamp( existing.getRequiredEMailSentStamp() );

		CFSecBuffSecUserEMConfBySentStampIdxKey newKeySentStampIdx = (CFSecBuffSecUserEMConfBySentStampIdxKey)schema.getCFSecBuffFactory().getFactorySecUserEMConf().newBySentStampIdxKey();
		newKeySentStampIdx.setRequiredEMailSentStamp( Buff.getRequiredEMailSentStamp() );

		CFSecBuffSecUserEMConfByNewAcctIdxKey existingKeyNewAcctIdx = (CFSecBuffSecUserEMConfByNewAcctIdxKey)schema.getCFSecBuffFactory().getFactorySecUserEMConf().newByNewAcctIdxKey();
		existingKeyNewAcctIdx.setRequiredNewAccount( existing.getRequiredNewAccount() );

		CFSecBuffSecUserEMConfByNewAcctIdxKey newKeyNewAcctIdx = (CFSecBuffSecUserEMConfByNewAcctIdxKey)schema.getCFSecBuffFactory().getFactorySecUserEMConf().newByNewAcctIdxKey();
		newKeyNewAcctIdx.setRequiredNewAccount( Buff.getRequiredNewAccount() );

		// Check unique indexes

		if( ! existingKeyUUuid6Idx.equals( newKeyUUuid6Idx ) ) {
			if( dictByUUuid6Idx.containsKey( newKeyUUuid6Idx ) ) {
				throw new CFLibUniqueIndexViolationException( getClass(),
					"updateSecUserEMConf",
					"SecUserEMConfUuid6Idx",
					"SecUserEMConfUuid6Idx",
					newKeyUUuid6Idx );
			}
		}

		// Validate foreign keys

		{
			boolean allNull = true;

			if( allNull ) {
				if( null == schema.getTableSecUser().readDerivedByIdIdx( Authorization,
						Buff.getRequiredSecUserId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						"updateSecUserEMConf",
						"Container",
						"Container",
						"SecUser",
						"SecUser",
						"SecUser",
						"SecUser",
						null );
				}
			}
		}

		// Update is valid

		Map< $iterate Columns ( lone implIJavaOptAtomType first implIJavaOptAtomType each implCommaIJavaOptAtomType empty empty )$, CFSecBuffSecUserEMConf > subdict;

		dictByPKey.remove( pkey );
		dictByPKey.put( pkey, Buff );

		dictByUUuid6Idx.remove( existingKeyUUuid6Idx );
		dictByUUuid6Idx.put( newKeyUUuid6Idx, Buff );

		subdict = dictByConfEMAddrIdx.get( existingKeyConfEMAddrIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictByConfEMAddrIdx.containsKey( newKeyConfEMAddrIdx ) ) {
			subdict = dictByConfEMAddrIdx.get( newKeyConfEMAddrIdx );
		}
		else {
			subdict = new HashMap< $iterate Columns ( lone implIJavaOptAtomType first implIJavaOptAtomType each implCommaIJavaOptAtomType empty empty )$, CFSecBuffSecUserEMConf >();
			dictByConfEMAddrIdx.put( newKeyConfEMAddrIdx, subdict );
		}
		subdict.put( pkey, Buff );

		subdict = dictBySentStampIdx.get( existingKeySentStampIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictBySentStampIdx.containsKey( newKeySentStampIdx ) ) {
			subdict = dictBySentStampIdx.get( newKeySentStampIdx );
		}
		else {
			subdict = new HashMap< $iterate Columns ( lone implIJavaOptAtomType first implIJavaOptAtomType each implCommaIJavaOptAtomType empty empty )$, CFSecBuffSecUserEMConf >();
			dictBySentStampIdx.put( newKeySentStampIdx, subdict );
		}
		subdict.put( pkey, Buff );

		subdict = dictByNewAcctIdx.get( existingKeyNewAcctIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictByNewAcctIdx.containsKey( newKeyNewAcctIdx ) ) {
			subdict = dictByNewAcctIdx.get( newKeyNewAcctIdx );
		}
		else {
			subdict = new HashMap< $iterate Columns ( lone implIJavaOptAtomType first implIJavaOptAtomType each implCommaIJavaOptAtomType empty empty )$, CFSecBuffSecUserEMConf >();
			dictByNewAcctIdx.put( newKeyNewAcctIdx, subdict );
		}
		subdict.put( pkey, Buff );

		return(Buff);
	}

	@Override
	public void deleteSecUserEMConf( ICFSecAuthorization Authorization,
		ICFSecSecUserEMConf iBuff )
	{
		final String S_ProcName = "CFSecRamSecUserEMConfTable.deleteSecUserEMConf() ";
		CFSecBuffSecUserEMConf Buff = (CFSecBuffSecUserEMConf)ensureRec(iBuff);
		int classCode;
		$iterate Columns ( lone implIJavaOptAtomType first implIJavaOptAtomType each implCommaIJavaOptAtomType empty empty )$ pkey = ($iterate Columns ( lone implIJavaOptAtomType first implIJavaOptAtomType each implCommaIJavaOptAtomType empty empty )$)(Buff.getPKey());
		CFSecBuffSecUserEMConf existing = dictByPKey.get( pkey );
		if( existing == null ) {
			return;
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() )
		{
			throw new CFLibCollisionDetectedException( getClass(),
				"deleteSecUserEMConf",
				pkey );
		}
		CFSecBuffSecUserEMConfByUUuid6IdxKey keyUUuid6Idx = (CFSecBuffSecUserEMConfByUUuid6IdxKey)schema.getCFSecBuffFactory().getFactorySecUserEMConf().newByUUuid6IdxKey();
		keyUUuid6Idx.setRequiredEMConfirmationUuid6( existing.getRequiredEMConfirmationUuid6() );

		CFSecBuffSecUserEMConfByConfEMAddrIdxKey keyConfEMAddrIdx = (CFSecBuffSecUserEMConfByConfEMAddrIdxKey)schema.getCFSecBuffFactory().getFactorySecUserEMConf().newByConfEMAddrIdxKey();
		keyConfEMAddrIdx.setRequiredConfirmEMailAddr( existing.getRequiredConfirmEMailAddr() );

		CFSecBuffSecUserEMConfBySentStampIdxKey keySentStampIdx = (CFSecBuffSecUserEMConfBySentStampIdxKey)schema.getCFSecBuffFactory().getFactorySecUserEMConf().newBySentStampIdxKey();
		keySentStampIdx.setRequiredEMailSentStamp( existing.getRequiredEMailSentStamp() );

		CFSecBuffSecUserEMConfByNewAcctIdxKey keyNewAcctIdx = (CFSecBuffSecUserEMConfByNewAcctIdxKey)schema.getCFSecBuffFactory().getFactorySecUserEMConf().newByNewAcctIdxKey();
		keyNewAcctIdx.setRequiredNewAccount( existing.getRequiredNewAccount() );

		// Validate reverse foreign keys

		// Delete is valid
		Map< $iterate Columns ( lone implIJavaOptAtomType first implIJavaOptAtomType each implCommaIJavaOptAtomType empty empty )$, CFSecBuffSecUserEMConf > subdict;

		dictByPKey.remove( pkey );

		dictByUUuid6Idx.remove( keyUUuid6Idx );

		subdict = dictByConfEMAddrIdx.get( keyConfEMAddrIdx );
		subdict.remove( pkey );

		subdict = dictBySentStampIdx.get( keySentStampIdx );
		subdict.remove( pkey );

		subdict = dictByNewAcctIdx.get( keyNewAcctIdx );
		subdict.remove( pkey );

	}
	@Override
	public void deleteSecUserEMConfByIdIdx( ICFSecAuthorization Authorization,
		$iterate Columns ( lone implIJavaOptAtomType first implIJavaOptAtomType each implCommaIJavaOptAtomType empty empty )$ argKey )
	{
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		CFSecBuffSecUserEMConf cur;
		LinkedList<CFSecBuffSecUserEMConf> matchSet = new LinkedList<CFSecBuffSecUserEMConf>();
		Iterator<CFSecBuffSecUserEMConf> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecUserEMConf> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecUserEMConf)(schema.getTableSecUserEMConf().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecUserId() ));
			deleteSecUserEMConf( Authorization, cur );
		}
	}

	@Override
	public void deleteSecUserEMConfByUUuid6Idx( ICFSecAuthorization Authorization,
		$iterate Columns ( lone implIJavaAtomType first implIJavaAtomType each implCommaIJavaAtomType empty empty )$ argEMConfirmationUuid6 )
	{
		CFSecBuffSecUserEMConfByUUuid6IdxKey key = (CFSecBuffSecUserEMConfByUUuid6IdxKey)schema.getCFSecBuffFactory().getFactorySecUserEMConf().newByUUuid6IdxKey();
		key.setRequiredEMConfirmationUuid6( argEMConfirmationUuid6 );
		deleteSecUserEMConfByUUuid6Idx( Authorization, key );
	}

	@Override
	public void deleteSecUserEMConfByUUuid6Idx( ICFSecAuthorization Authorization,
		ICFSecSecUserEMConfByUUuid6IdxKey argKey )
	{
		CFSecBuffSecUserEMConf cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffSecUserEMConf> matchSet = new LinkedList<CFSecBuffSecUserEMConf>();
		Iterator<CFSecBuffSecUserEMConf> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecUserEMConf> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecUserEMConf)(schema.getTableSecUserEMConf().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecUserId() ));
			deleteSecUserEMConf( Authorization, cur );
		}
	}

	@Override
	public void deleteSecUserEMConfByConfEMAddrIdx( ICFSecAuthorization Authorization,
		$iterate Columns ( lone implIJavaAtomType first implIJavaAtomType each implCommaIJavaAtomType empty empty )$ argConfirmEMailAddr )
	{
		CFSecBuffSecUserEMConfByConfEMAddrIdxKey key = (CFSecBuffSecUserEMConfByConfEMAddrIdxKey)schema.getCFSecBuffFactory().getFactorySecUserEMConf().newByConfEMAddrIdxKey();
		key.setRequiredConfirmEMailAddr( argConfirmEMailAddr );
		deleteSecUserEMConfByConfEMAddrIdx( Authorization, key );
	}

	@Override
	public void deleteSecUserEMConfByConfEMAddrIdx( ICFSecAuthorization Authorization,
		ICFSecSecUserEMConfByConfEMAddrIdxKey argKey )
	{
		CFSecBuffSecUserEMConf cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffSecUserEMConf> matchSet = new LinkedList<CFSecBuffSecUserEMConf>();
		Iterator<CFSecBuffSecUserEMConf> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecUserEMConf> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecUserEMConf)(schema.getTableSecUserEMConf().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecUserId() ));
			deleteSecUserEMConf( Authorization, cur );
		}
	}

	@Override
	public void deleteSecUserEMConfBySentStampIdx( ICFSecAuthorization Authorization,
		$iterate Columns ( lone implIJavaAtomType first implIJavaAtomType each implCommaIJavaAtomType empty empty )$ argEMailSentStamp )
	{
		CFSecBuffSecUserEMConfBySentStampIdxKey key = (CFSecBuffSecUserEMConfBySentStampIdxKey)schema.getCFSecBuffFactory().getFactorySecUserEMConf().newBySentStampIdxKey();
		key.setRequiredEMailSentStamp( argEMailSentStamp );
		deleteSecUserEMConfBySentStampIdx( Authorization, key );
	}

	@Override
	public void deleteSecUserEMConfBySentStampIdx( ICFSecAuthorization Authorization,
		ICFSecSecUserEMConfBySentStampIdxKey argKey )
	{
		CFSecBuffSecUserEMConf cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffSecUserEMConf> matchSet = new LinkedList<CFSecBuffSecUserEMConf>();
		Iterator<CFSecBuffSecUserEMConf> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecUserEMConf> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecUserEMConf)(schema.getTableSecUserEMConf().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecUserId() ));
			deleteSecUserEMConf( Authorization, cur );
		}
	}

	@Override
	public void deleteSecUserEMConfByNewAcctIdx( ICFSecAuthorization Authorization,
		$iterate Columns ( lone implIJavaAtomType first implIJavaAtomType each implCommaIJavaAtomType empty empty )$ argNewAccount )
	{
		CFSecBuffSecUserEMConfByNewAcctIdxKey key = (CFSecBuffSecUserEMConfByNewAcctIdxKey)schema.getCFSecBuffFactory().getFactorySecUserEMConf().newByNewAcctIdxKey();
		key.setRequiredNewAccount( argNewAccount );
		deleteSecUserEMConfByNewAcctIdx( Authorization, key );
	}

	@Override
	public void deleteSecUserEMConfByNewAcctIdx( ICFSecAuthorization Authorization,
		ICFSecSecUserEMConfByNewAcctIdxKey argKey )
	{
		CFSecBuffSecUserEMConf cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffSecUserEMConf> matchSet = new LinkedList<CFSecBuffSecUserEMConf>();
		Iterator<CFSecBuffSecUserEMConf> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecUserEMConf> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecUserEMConf)(schema.getTableSecUserEMConf().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecUserId() ));
			deleteSecUserEMConf( Authorization, cur );
		}
	}
}
