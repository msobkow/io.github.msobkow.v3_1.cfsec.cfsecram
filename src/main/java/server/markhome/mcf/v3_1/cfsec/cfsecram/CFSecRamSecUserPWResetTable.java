
// Description: Java 25 in-memory RAM DbIO implementation for SecUserPWReset.

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
 *	CFSecRamSecUserPWResetTable in-memory RAM DbIO implementation
 *	for SecUserPWReset.
 */
public class CFSecRamSecUserPWResetTable
	implements ICFSecSecUserPWResetTable
{
	private ICFSecSchema schema;
	private Map< ICFLibKeyHash256,
				CFSecBuffSecUserPWReset > dictByPKey
		= new HashMap< ICFLibKeyHash256,
				CFSecBuffSecUserPWReset >();
	private Map< CFSecBuffSecUserPWResetByUUuid6IdxKey,
			CFSecBuffSecUserPWReset > dictByUUuid6Idx
		= new HashMap< CFSecBuffSecUserPWResetByUUuid6IdxKey,
			CFSecBuffSecUserPWReset >();
	private Map< CFSecBuffSecUserPWResetBySentEMAddrIdxKey,
				Map< ICFLibKeyHash256,
					CFSecBuffSecUserPWReset >> dictBySentEMAddrIdx
		= new HashMap< CFSecBuffSecUserPWResetBySentEMAddrIdxKey,
				Map< ICFLibKeyHash256,
					CFSecBuffSecUserPWReset >>();
	private Map< CFSecBuffSecUserPWResetByNewAcctIdxKey,
				Map< ICFLibKeyHash256,
					CFSecBuffSecUserPWReset >> dictByNewAcctIdx
		= new HashMap< CFSecBuffSecUserPWResetByNewAcctIdxKey,
				Map< ICFLibKeyHash256,
					CFSecBuffSecUserPWReset >>();

	public CFSecRamSecUserPWResetTable( ICFSecSchema argSchema ) {
		schema = argSchema;
	}

	public CFSecBuffSecUserPWReset ensureRec(ICFSecSecUserPWReset rec) {
		return (((CFSecBuffSecUserPWResetFactoryService)(schema.getCFSecBuffFactory().getFactorySecUserPWReset())).ensureRec(rec));
	}

	@Override
	public ICFSecSecUserPWReset createSecUserPWReset( ICFSecAuthorization Authorization,
		ICFSecSecUserPWReset iBuff )
	{
		final String S_ProcName = "createSecUserPWReset";
		
		CFSecBuffSecUserPWReset Buff = (CFSecBuffSecUserPWReset)ensureRec(iBuff);
		ICFLibKeyHash256 pkey;
		pkey = Buff.getRequiredSecUserId();
		pkey = Buff.getRequiredSecUserId();
		Buff.setRequiredContainerUser( pkey );
		Buff.setRequiredSecUserId( pkey );
		CFSecBuffSecUserPWResetByUUuid6IdxKey keyUUuid6Idx = (CFSecBuffSecUserPWResetByUUuid6IdxKey)schema.getCFSecBuffFactory().getFactorySecUserPWReset().newByUUuid6IdxKey();
		keyUUuid6Idx.setRequiredPasswordResetUuid6( Buff.getRequiredPasswordResetUuid6() );

		CFSecBuffSecUserPWResetBySentEMAddrIdxKey keySentEMAddrIdx = (CFSecBuffSecUserPWResetBySentEMAddrIdxKey)schema.getCFSecBuffFactory().getFactorySecUserPWReset().newBySentEMAddrIdxKey();
		keySentEMAddrIdx.setRequiredSentToEMailAddr( Buff.getRequiredSentToEMailAddr() );

		CFSecBuffSecUserPWResetByNewAcctIdxKey keyNewAcctIdx = (CFSecBuffSecUserPWResetByNewAcctIdxKey)schema.getCFSecBuffFactory().getFactorySecUserPWReset().newByNewAcctIdxKey();
		keyNewAcctIdx.setRequiredNewAccount( Buff.getRequiredNewAccount() );

		// Validate unique indexes

		if( dictByPKey.containsKey( pkey ) ) {
			throw new CFLibPrimaryKeyNotNewException( getClass(), S_ProcName, pkey );
		}

		if( dictByUUuid6Idx.containsKey( keyUUuid6Idx ) ) {
			throw new CFLibUniqueIndexViolationException( getClass(),
				S_ProcName,
				"SecUserPWResetUuid6Idx",
				"SecUserPWResetUuid6Idx",
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

		Map< ICFLibKeyHash256, CFSecBuffSecUserPWReset > subdictSentEMAddrIdx;
		if( dictBySentEMAddrIdx.containsKey( keySentEMAddrIdx ) ) {
			subdictSentEMAddrIdx = dictBySentEMAddrIdx.get( keySentEMAddrIdx );
		}
		else {
			subdictSentEMAddrIdx = new HashMap< ICFLibKeyHash256, CFSecBuffSecUserPWReset >();
			dictBySentEMAddrIdx.put( keySentEMAddrIdx, subdictSentEMAddrIdx );
		}
		subdictSentEMAddrIdx.put( pkey, Buff );

		Map< ICFLibKeyHash256, CFSecBuffSecUserPWReset > subdictNewAcctIdx;
		if( dictByNewAcctIdx.containsKey( keyNewAcctIdx ) ) {
			subdictNewAcctIdx = dictByNewAcctIdx.get( keyNewAcctIdx );
		}
		else {
			subdictNewAcctIdx = new HashMap< ICFLibKeyHash256, CFSecBuffSecUserPWReset >();
			dictByNewAcctIdx.put( keyNewAcctIdx, subdictNewAcctIdx );
		}
		subdictNewAcctIdx.put( pkey, Buff );

		if (Buff == null) {
			return( null );
		}
		else {
			int classCode = Buff.getClassCode();
			if (classCode == ICFSecSecUserPWReset.CLASS_CODE) {
				CFSecBuffSecUserPWReset retbuff = ((CFSecBuffSecUserPWReset)(schema.getCFSecBuffFactory().getFactorySecUserPWReset().newRec()));
				retbuff.set(Buff);
				return( retbuff );
			}
			else {
				throw new CFLibUnsupportedClassException(getClass(), S_ProcName, "-create-buff-cloning-", (Integer)classCode, "Classcode not recognized: " + Integer.toString(classCode));
			}
		}
	}

	@Override
	public ICFSecSecUserPWReset readDerived( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 PKey )
	{
		final String S_ProcName = "CFSecRamSecUserPWReset.readDerived";
		ICFSecSecUserPWReset buff;
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
	public ICFSecSecUserPWReset lockDerived( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 PKey )
	{
		final String S_ProcName = "CFSecRamSecUserPWReset.lockDerived";
		ICFSecSecUserPWReset buff;
		if( dictByPKey.containsKey( PKey ) ) {
			buff = dictByPKey.get( PKey );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecUserPWReset[] readAllDerived( ICFSecAuthorization Authorization ) {
		final String S_ProcName = "CFSecRamSecUserPWReset.readAllDerived";
		ICFSecSecUserPWReset[] retList = new ICFSecSecUserPWReset[ dictByPKey.values().size() ];
		Iterator< CFSecBuffSecUserPWReset > iter = dictByPKey.values().iterator();
		int idx = 0;
		while( iter.hasNext() ) {
			retList[ idx++ ] = iter.next();
		}
		return( retList );
	}

	@Override
	public ICFSecSecUserPWReset readDerivedByUUuid6Idx( ICFSecAuthorization Authorization,
		ICFLibUuid6 PasswordResetUuid6 )
	{
		final String S_ProcName = "CFSecRamSecUserPWReset.readDerivedByUUuid6Idx";
		CFSecBuffSecUserPWResetByUUuid6IdxKey key = (CFSecBuffSecUserPWResetByUUuid6IdxKey)schema.getCFSecBuffFactory().getFactorySecUserPWReset().newByUUuid6IdxKey();

		key.setRequiredPasswordResetUuid6( PasswordResetUuid6 );
		ICFSecSecUserPWReset buff;
		if( dictByUUuid6Idx.containsKey( key ) ) {
			buff = dictByUUuid6Idx.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecUserPWReset[] readDerivedBySentEMAddrIdx( ICFSecAuthorization Authorization,
		String SentToEMailAddr )
	{
		final String S_ProcName = "CFSecRamSecUserPWReset.readDerivedBySentEMAddrIdx";
		CFSecBuffSecUserPWResetBySentEMAddrIdxKey key = (CFSecBuffSecUserPWResetBySentEMAddrIdxKey)schema.getCFSecBuffFactory().getFactorySecUserPWReset().newBySentEMAddrIdxKey();

		key.setRequiredSentToEMailAddr( SentToEMailAddr );
		ICFSecSecUserPWReset[] recArray;
		if( dictBySentEMAddrIdx.containsKey( key ) ) {
			Map< ICFLibKeyHash256, CFSecBuffSecUserPWReset > subdictSentEMAddrIdx
				= dictBySentEMAddrIdx.get( key );
			recArray = new ICFSecSecUserPWReset[ subdictSentEMAddrIdx.size() ];
			Iterator< CFSecBuffSecUserPWReset > iter = subdictSentEMAddrIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< ICFLibKeyHash256, CFSecBuffSecUserPWReset > subdictSentEMAddrIdx
				= new HashMap< ICFLibKeyHash256, CFSecBuffSecUserPWReset >();
			dictBySentEMAddrIdx.put( key, subdictSentEMAddrIdx );
			recArray = new ICFSecSecUserPWReset[0];
		}
		return( recArray );
	}

	@Override
	public ICFSecSecUserPWReset[] readDerivedByNewAcctIdx( ICFSecAuthorization Authorization,
		boolean NewAccount )
	{
		final String S_ProcName = "CFSecRamSecUserPWReset.readDerivedByNewAcctIdx";
		CFSecBuffSecUserPWResetByNewAcctIdxKey key = (CFSecBuffSecUserPWResetByNewAcctIdxKey)schema.getCFSecBuffFactory().getFactorySecUserPWReset().newByNewAcctIdxKey();

		key.setRequiredNewAccount( NewAccount );
		ICFSecSecUserPWReset[] recArray;
		if( dictByNewAcctIdx.containsKey( key ) ) {
			Map< ICFLibKeyHash256, CFSecBuffSecUserPWReset > subdictNewAcctIdx
				= dictByNewAcctIdx.get( key );
			recArray = new ICFSecSecUserPWReset[ subdictNewAcctIdx.size() ];
			Iterator< CFSecBuffSecUserPWReset > iter = subdictNewAcctIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< ICFLibKeyHash256, CFSecBuffSecUserPWReset > subdictNewAcctIdx
				= new HashMap< ICFLibKeyHash256, CFSecBuffSecUserPWReset >();
			dictByNewAcctIdx.put( key, subdictNewAcctIdx );
			recArray = new ICFSecSecUserPWReset[0];
		}
		return( recArray );
	}

	@Override
	public ICFSecSecUserPWReset readDerivedByIdIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 SecUserId )
	{
		final String S_ProcName = "CFSecRamSecUserPWReset.readDerivedByIdIdx() ";
		ICFSecSecUserPWReset buff;
		if( dictByPKey.containsKey( SecUserId ) ) {
			buff = dictByPKey.get( SecUserId );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecUserPWReset readRec( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 PKey )
	{
		final String S_ProcName = "CFSecRamSecUserPWReset.readRec";
		ICFSecSecUserPWReset buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecSecUserPWReset.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecUserPWReset lockRec( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 PKey )
	{
		final String S_ProcName = "lockRec";
		ICFSecSecUserPWReset buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecSecUserPWReset.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecUserPWReset[] readAllRec( ICFSecAuthorization Authorization )
	{
		final String S_ProcName = "CFSecRamSecUserPWReset.readAllRec";
		ICFSecSecUserPWReset buff;
		ArrayList<ICFSecSecUserPWReset> filteredList = new ArrayList<ICFSecSecUserPWReset>();
		ICFSecSecUserPWReset[] buffList = readAllDerived( Authorization );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecUserPWReset.CLASS_CODE ) ) {
				filteredList.add( buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecUserPWReset[0] ) );
	}

	/**
	 *	Read a page of all the specific SecUserPWReset buffer instances.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@return All the specific SecUserPWReset instances in the database accessible for the Authorization.
	 */
	@Override
	public ICFSecSecUserPWReset[] pageAllRec( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 priorSecUserId )
	{
		final String S_ProcName = "pageAllRec";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	@Override
	public ICFSecSecUserPWReset readRecByIdIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 SecUserId )
	{
		final String S_ProcName = "CFSecRamSecUserPWReset.readRecByIdIdx() ";
		ICFSecSecUserPWReset buff = readDerivedByIdIdx( Authorization,
			SecUserId );
		if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecUserPWReset.CLASS_CODE ) ) {
			return( (ICFSecSecUserPWReset)buff );
		}
		else {
			return( null );
		}
	}

	@Override
	public ICFSecSecUserPWReset readRecByUUuid6Idx( ICFSecAuthorization Authorization,
		ICFLibUuid6 PasswordResetUuid6 )
	{
		final String S_ProcName = "CFSecRamSecUserPWReset.readRecByUUuid6Idx() ";
		ICFSecSecUserPWReset buff = readDerivedByUUuid6Idx( Authorization,
			PasswordResetUuid6 );
		if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecUserPWReset.CLASS_CODE ) ) {
			return( (ICFSecSecUserPWReset)buff );
		}
		else {
			return( null );
		}
	}

	@Override
	public ICFSecSecUserPWReset[] readRecBySentEMAddrIdx( ICFSecAuthorization Authorization,
		String SentToEMailAddr )
	{
		final String S_ProcName = "CFSecRamSecUserPWReset.readRecBySentEMAddrIdx() ";
		ICFSecSecUserPWReset buff;
		ArrayList<ICFSecSecUserPWReset> filteredList = new ArrayList<ICFSecSecUserPWReset>();
		ICFSecSecUserPWReset[] buffList = readDerivedBySentEMAddrIdx( Authorization,
			SentToEMailAddr );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecUserPWReset.CLASS_CODE ) ) {
				filteredList.add( (ICFSecSecUserPWReset)buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecUserPWReset[0] ) );
	}

	@Override
	public ICFSecSecUserPWReset[] readRecByNewAcctIdx( ICFSecAuthorization Authorization,
		boolean NewAccount )
	{
		final String S_ProcName = "CFSecRamSecUserPWReset.readRecByNewAcctIdx() ";
		ICFSecSecUserPWReset buff;
		ArrayList<ICFSecSecUserPWReset> filteredList = new ArrayList<ICFSecSecUserPWReset>();
		ICFSecSecUserPWReset[] buffList = readDerivedByNewAcctIdx( Authorization,
			NewAccount );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecUserPWReset.CLASS_CODE ) ) {
				filteredList.add( (ICFSecSecUserPWReset)buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecUserPWReset[0] ) );
	}

	/**
	 *	Read a page array of the specific SecUserPWReset buffer instances identified by the duplicate key SentEMAddrIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	SentToEMailAddr	The SecUserPWReset key attribute of the instance generating the id.
	 *
	 *	@return An array of derived buffer instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecSecUserPWReset[] pageRecBySentEMAddrIdx( ICFSecAuthorization Authorization,
		String SentToEMailAddr,
		ICFLibKeyHash256 priorSecUserId )
	{
		final String S_ProcName = "pageRecBySentEMAddrIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	/**
	 *	Read a page array of the specific SecUserPWReset buffer instances identified by the duplicate key NewAcctIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	NewAccount	The SecUserPWReset key attribute of the instance generating the id.
	 *
	 *	@return An array of derived buffer instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecSecUserPWReset[] pageRecByNewAcctIdx( ICFSecAuthorization Authorization,
		boolean NewAccount,
		ICFLibKeyHash256 priorSecUserId )
	{
		final String S_ProcName = "pageRecByNewAcctIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	public ICFSecSecUserPWReset updateSecUserPWReset( ICFSecAuthorization Authorization,
		ICFSecSecUserPWReset iBuff )
	{
		CFSecBuffSecUserPWReset Buff = (CFSecBuffSecUserPWReset)ensureRec(iBuff);
		ICFLibKeyHash256 pkey = (ICFLibKeyHash256)Buff.getPKey();
		CFSecBuffSecUserPWReset existing = dictByPKey.get( pkey );
		if( existing == null ) {
			throw new CFLibStaleCacheDetectedException( getClass(),
				"updateSecUserPWReset",
				"Existing record not found",
				"Existing record not found",
				"SecUserPWReset",
				"SecUserPWReset",
				pkey );
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() ) {
			throw new CFLibCollisionDetectedException( getClass(),
				"updateSecUserPWReset",
				pkey );
		}
		Buff.setRequiredRevision( Buff.getRequiredRevision() + 1 );
		CFSecBuffSecUserPWResetByUUuid6IdxKey existingKeyUUuid6Idx = (CFSecBuffSecUserPWResetByUUuid6IdxKey)schema.getCFSecBuffFactory().getFactorySecUserPWReset().newByUUuid6IdxKey();
		existingKeyUUuid6Idx.setRequiredPasswordResetUuid6( existing.getRequiredPasswordResetUuid6() );

		CFSecBuffSecUserPWResetByUUuid6IdxKey newKeyUUuid6Idx = (CFSecBuffSecUserPWResetByUUuid6IdxKey)schema.getCFSecBuffFactory().getFactorySecUserPWReset().newByUUuid6IdxKey();
		newKeyUUuid6Idx.setRequiredPasswordResetUuid6( Buff.getRequiredPasswordResetUuid6() );

		CFSecBuffSecUserPWResetBySentEMAddrIdxKey existingKeySentEMAddrIdx = (CFSecBuffSecUserPWResetBySentEMAddrIdxKey)schema.getCFSecBuffFactory().getFactorySecUserPWReset().newBySentEMAddrIdxKey();
		existingKeySentEMAddrIdx.setRequiredSentToEMailAddr( existing.getRequiredSentToEMailAddr() );

		CFSecBuffSecUserPWResetBySentEMAddrIdxKey newKeySentEMAddrIdx = (CFSecBuffSecUserPWResetBySentEMAddrIdxKey)schema.getCFSecBuffFactory().getFactorySecUserPWReset().newBySentEMAddrIdxKey();
		newKeySentEMAddrIdx.setRequiredSentToEMailAddr( Buff.getRequiredSentToEMailAddr() );

		CFSecBuffSecUserPWResetByNewAcctIdxKey existingKeyNewAcctIdx = (CFSecBuffSecUserPWResetByNewAcctIdxKey)schema.getCFSecBuffFactory().getFactorySecUserPWReset().newByNewAcctIdxKey();
		existingKeyNewAcctIdx.setRequiredNewAccount( existing.getRequiredNewAccount() );

		CFSecBuffSecUserPWResetByNewAcctIdxKey newKeyNewAcctIdx = (CFSecBuffSecUserPWResetByNewAcctIdxKey)schema.getCFSecBuffFactory().getFactorySecUserPWReset().newByNewAcctIdxKey();
		newKeyNewAcctIdx.setRequiredNewAccount( Buff.getRequiredNewAccount() );

		// Check unique indexes

		if( ! existingKeyUUuid6Idx.equals( newKeyUUuid6Idx ) ) {
			if( dictByUUuid6Idx.containsKey( newKeyUUuid6Idx ) ) {
				throw new CFLibUniqueIndexViolationException( getClass(),
					"updateSecUserPWReset",
					"SecUserPWResetUuid6Idx",
					"SecUserPWResetUuid6Idx",
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
						"updateSecUserPWReset",
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

		Map< ICFLibKeyHash256, CFSecBuffSecUserPWReset > subdict;

		dictByPKey.remove( pkey );
		dictByPKey.put( pkey, Buff );

		dictByUUuid6Idx.remove( existingKeyUUuid6Idx );
		dictByUUuid6Idx.put( newKeyUUuid6Idx, Buff );

		subdict = dictBySentEMAddrIdx.get( existingKeySentEMAddrIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictBySentEMAddrIdx.containsKey( newKeySentEMAddrIdx ) ) {
			subdict = dictBySentEMAddrIdx.get( newKeySentEMAddrIdx );
		}
		else {
			subdict = new HashMap< ICFLibKeyHash256, CFSecBuffSecUserPWReset >();
			dictBySentEMAddrIdx.put( newKeySentEMAddrIdx, subdict );
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
			subdict = new HashMap< ICFLibKeyHash256, CFSecBuffSecUserPWReset >();
			dictByNewAcctIdx.put( newKeyNewAcctIdx, subdict );
		}
		subdict.put( pkey, Buff );

		return(Buff);
	}

	@Override
	public void deleteSecUserPWReset( ICFSecAuthorization Authorization,
		ICFSecSecUserPWReset iBuff )
	{
		final String S_ProcName = "CFSecRamSecUserPWResetTable.deleteSecUserPWReset() ";
		CFSecBuffSecUserPWReset Buff = (CFSecBuffSecUserPWReset)ensureRec(iBuff);
		int classCode;
		ICFLibKeyHash256 pkey = (ICFLibKeyHash256)(Buff.getPKey());
		CFSecBuffSecUserPWReset existing = dictByPKey.get( pkey );
		if( existing == null ) {
			return;
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() )
		{
			throw new CFLibCollisionDetectedException( getClass(),
				"deleteSecUserPWReset",
				pkey );
		}
		CFSecBuffSecUserPWResetByUUuid6IdxKey keyUUuid6Idx = (CFSecBuffSecUserPWResetByUUuid6IdxKey)schema.getCFSecBuffFactory().getFactorySecUserPWReset().newByUUuid6IdxKey();
		keyUUuid6Idx.setRequiredPasswordResetUuid6( existing.getRequiredPasswordResetUuid6() );

		CFSecBuffSecUserPWResetBySentEMAddrIdxKey keySentEMAddrIdx = (CFSecBuffSecUserPWResetBySentEMAddrIdxKey)schema.getCFSecBuffFactory().getFactorySecUserPWReset().newBySentEMAddrIdxKey();
		keySentEMAddrIdx.setRequiredSentToEMailAddr( existing.getRequiredSentToEMailAddr() );

		CFSecBuffSecUserPWResetByNewAcctIdxKey keyNewAcctIdx = (CFSecBuffSecUserPWResetByNewAcctIdxKey)schema.getCFSecBuffFactory().getFactorySecUserPWReset().newByNewAcctIdxKey();
		keyNewAcctIdx.setRequiredNewAccount( existing.getRequiredNewAccount() );

		// Validate reverse foreign keys

		// Delete is valid
		Map< ICFLibKeyHash256, CFSecBuffSecUserPWReset > subdict;

		dictByPKey.remove( pkey );

		dictByUUuid6Idx.remove( keyUUuid6Idx );

		subdict = dictBySentEMAddrIdx.get( keySentEMAddrIdx );
		subdict.remove( pkey );

		subdict = dictByNewAcctIdx.get( keyNewAcctIdx );
		subdict.remove( pkey );

	}
	@Override
	public void deleteSecUserPWResetByIdIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 argKey )
	{
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		CFSecBuffSecUserPWReset cur;
		LinkedList<CFSecBuffSecUserPWReset> matchSet = new LinkedList<CFSecBuffSecUserPWReset>();
		Iterator<CFSecBuffSecUserPWReset> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecUserPWReset> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecUserPWReset)(schema.getTableSecUserPWReset().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecUserId() ));
			deleteSecUserPWReset( Authorization, cur );
		}
	}

	@Override
	public void deleteSecUserPWResetByUUuid6Idx( ICFSecAuthorization Authorization,
		ICFLibUuid6 argPasswordResetUuid6 )
	{
		CFSecBuffSecUserPWResetByUUuid6IdxKey key = (CFSecBuffSecUserPWResetByUUuid6IdxKey)schema.getCFSecBuffFactory().getFactorySecUserPWReset().newByUUuid6IdxKey();
		key.setRequiredPasswordResetUuid6( argPasswordResetUuid6 );
		deleteSecUserPWResetByUUuid6Idx( Authorization, key );
	}

	@Override
	public void deleteSecUserPWResetByUUuid6Idx( ICFSecAuthorization Authorization,
		ICFSecSecUserPWResetByUUuid6IdxKey argKey )
	{
		CFSecBuffSecUserPWReset cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffSecUserPWReset> matchSet = new LinkedList<CFSecBuffSecUserPWReset>();
		Iterator<CFSecBuffSecUserPWReset> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecUserPWReset> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecUserPWReset)(schema.getTableSecUserPWReset().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecUserId() ));
			deleteSecUserPWReset( Authorization, cur );
		}
	}

	@Override
	public void deleteSecUserPWResetBySentEMAddrIdx( ICFSecAuthorization Authorization,
		String argSentToEMailAddr )
	{
		CFSecBuffSecUserPWResetBySentEMAddrIdxKey key = (CFSecBuffSecUserPWResetBySentEMAddrIdxKey)schema.getCFSecBuffFactory().getFactorySecUserPWReset().newBySentEMAddrIdxKey();
		key.setRequiredSentToEMailAddr( argSentToEMailAddr );
		deleteSecUserPWResetBySentEMAddrIdx( Authorization, key );
	}

	@Override
	public void deleteSecUserPWResetBySentEMAddrIdx( ICFSecAuthorization Authorization,
		ICFSecSecUserPWResetBySentEMAddrIdxKey argKey )
	{
		CFSecBuffSecUserPWReset cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffSecUserPWReset> matchSet = new LinkedList<CFSecBuffSecUserPWReset>();
		Iterator<CFSecBuffSecUserPWReset> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecUserPWReset> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecUserPWReset)(schema.getTableSecUserPWReset().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecUserId() ));
			deleteSecUserPWReset( Authorization, cur );
		}
	}

	@Override
	public void deleteSecUserPWResetByNewAcctIdx( ICFSecAuthorization Authorization,
		boolean argNewAccount )
	{
		CFSecBuffSecUserPWResetByNewAcctIdxKey key = (CFSecBuffSecUserPWResetByNewAcctIdxKey)schema.getCFSecBuffFactory().getFactorySecUserPWReset().newByNewAcctIdxKey();
		key.setRequiredNewAccount( argNewAccount );
		deleteSecUserPWResetByNewAcctIdx( Authorization, key );
	}

	@Override
	public void deleteSecUserPWResetByNewAcctIdx( ICFSecAuthorization Authorization,
		ICFSecSecUserPWResetByNewAcctIdxKey argKey )
	{
		CFSecBuffSecUserPWReset cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffSecUserPWReset> matchSet = new LinkedList<CFSecBuffSecUserPWReset>();
		Iterator<CFSecBuffSecUserPWReset> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecUserPWReset> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecUserPWReset)(schema.getTableSecUserPWReset().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecUserId() ));
			deleteSecUserPWReset( Authorization, cur );
		}
	}
}
