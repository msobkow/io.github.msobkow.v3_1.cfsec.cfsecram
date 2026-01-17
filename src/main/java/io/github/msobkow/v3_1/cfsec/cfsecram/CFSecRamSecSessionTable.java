
// Description: Java 25 in-memory RAM DbIO implementation for SecSession.

/*
 *	io.github.msobkow.CFSec
 *
 *	Copyright (c) 2016-2026 Mark Stephen Sobkow
 *	
 *	Mark's Code Fractal 3.1 CFSec - Security Services
 *	
 *	This file is part of Mark's Code Fractal CFSec.
 *	
 *	Mark's Code Fractal CFSec is available under dual commercial license from
 *	Mark Stephen Sobkow, or under the terms of the GNU Library General Public License,
 *	Version 3 or later.
 *	
 *	Mark's Code Fractal CFSec is free software: you can redistribute it and/or
 *	modify it under the terms of the GNU Library General Public License as published by
 *	the Free Software Foundation, either version 3 of the License, or
 *	(at your option) any later version.
 *	
 *	Mark's Code Fractal CFSec is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *	
 *	You should have received a copy of the GNU Library General Public License
 *	along with Mark's Code Fractal CFSec.  If not, see <https://www.gnu.org/licenses/>.
 *	
 *	If you wish to modify and use this code without publishing your changes in order to
 *	tie it to proprietary code, please contact Mark Stephen Sobkow
 *	for a commercial license at mark.sobkow@gmail.com
 *	
 */

package io.github.msobkow.v3_1.cfsec.cfsecram;

import java.math.*;
import java.sql.*;
import java.text.*;
import java.util.*;
import org.apache.commons.codec.binary.Base64;
import io.github.msobkow.v3_1.cflib.*;
import io.github.msobkow.v3_1.cflib.dbutil.*;

import io.github.msobkow.v3_1.cfsec.cfsec.*;
import io.github.msobkow.v3_1.cfsec.cfsecobj.*;
import io.github.msobkow.v3_1.cfsec.cfsecobj.*;

/*
 *	CFSecRamSecSessionTable in-memory RAM DbIO implementation
 *	for SecSession.
 */
public class CFSecRamSecSessionTable
	implements ICFSecSecSessionTable
{
	private ICFSecSchema schema;
	private Map< CFSecSecSessionPKey,
				CFSecSecSessionBuff > dictByPKey
		= new HashMap< CFSecSecSessionPKey,
				CFSecSecSessionBuff >();
	private Map< CFSecSecSessionBySecUserIdxKey,
				Map< CFSecSecSessionPKey,
					CFSecSecSessionBuff >> dictBySecUserIdx
		= new HashMap< CFSecSecSessionBySecUserIdxKey,
				Map< CFSecSecSessionPKey,
					CFSecSecSessionBuff >>();
	private Map< CFSecSecSessionBySecDevIdxKey,
				Map< CFSecSecSessionPKey,
					CFSecSecSessionBuff >> dictBySecDevIdx
		= new HashMap< CFSecSecSessionBySecDevIdxKey,
				Map< CFSecSecSessionPKey,
					CFSecSecSessionBuff >>();
	private Map< CFSecSecSessionByStartIdxKey,
			CFSecSecSessionBuff > dictByStartIdx
		= new HashMap< CFSecSecSessionByStartIdxKey,
			CFSecSecSessionBuff >();
	private Map< CFSecSecSessionByFinishIdxKey,
				Map< CFSecSecSessionPKey,
					CFSecSecSessionBuff >> dictByFinishIdx
		= new HashMap< CFSecSecSessionByFinishIdxKey,
				Map< CFSecSecSessionPKey,
					CFSecSecSessionBuff >>();
	private Map< CFSecSecSessionBySecProxyIdxKey,
				Map< CFSecSecSessionPKey,
					CFSecSecSessionBuff >> dictBySecProxyIdx
		= new HashMap< CFSecSecSessionBySecProxyIdxKey,
				Map< CFSecSecSessionPKey,
					CFSecSecSessionBuff >>();

	public CFSecRamSecSessionTable( ICFSecSchema argSchema ) {
		schema = argSchema;
	}

	public void createSecSession( CFSecAuthorization Authorization,
		CFSecSecSessionBuff Buff )
	{
		final String S_ProcName = "createSecSession";
		CFSecSecSessionPKey pkey = schema.getFactorySecSession().newPKey();
		pkey.setRequiredSecSessionId( schema.nextSecSessionIdGen() );
		Buff.setRequiredSecSessionId( pkey.getRequiredSecSessionId() );
		CFSecSecSessionBySecUserIdxKey keySecUserIdx = schema.getFactorySecSession().newSecUserIdxKey();
		keySecUserIdx.setRequiredSecUserId( Buff.getRequiredSecUserId() );

		CFSecSecSessionBySecDevIdxKey keySecDevIdx = schema.getFactorySecSession().newSecDevIdxKey();
		keySecDevIdx.setRequiredSecUserId( Buff.getRequiredSecUserId() );
		keySecDevIdx.setOptionalSecDevName( Buff.getOptionalSecDevName() );

		CFSecSecSessionByStartIdxKey keyStartIdx = schema.getFactorySecSession().newStartIdxKey();
		keyStartIdx.setRequiredSecUserId( Buff.getRequiredSecUserId() );
		keyStartIdx.setRequiredStart( Buff.getRequiredStart() );

		CFSecSecSessionByFinishIdxKey keyFinishIdx = schema.getFactorySecSession().newFinishIdxKey();
		keyFinishIdx.setRequiredSecUserId( Buff.getRequiredSecUserId() );
		keyFinishIdx.setOptionalFinish( Buff.getOptionalFinish() );

		CFSecSecSessionBySecProxyIdxKey keySecProxyIdx = schema.getFactorySecSession().newSecProxyIdxKey();
		keySecProxyIdx.setOptionalSecProxyId( Buff.getOptionalSecProxyId() );

		// Validate unique indexes

		if( dictByPKey.containsKey( pkey ) ) {
			throw new CFLibPrimaryKeyNotNewException( getClass(), S_ProcName, pkey );
		}

		if( dictByStartIdx.containsKey( keyStartIdx ) ) {
			throw new CFLibUniqueIndexViolationException( getClass(),
				S_ProcName,
				"SessionStartIdx",
				keyStartIdx );
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
						"SecSessionSecUser",
						"SecUser",
						null );
				}
			}
		}

		// Proceed with adding the new record

		dictByPKey.put( pkey, Buff );

		Map< CFSecSecSessionPKey, CFSecSecSessionBuff > subdictSecUserIdx;
		if( dictBySecUserIdx.containsKey( keySecUserIdx ) ) {
			subdictSecUserIdx = dictBySecUserIdx.get( keySecUserIdx );
		}
		else {
			subdictSecUserIdx = new HashMap< CFSecSecSessionPKey, CFSecSecSessionBuff >();
			dictBySecUserIdx.put( keySecUserIdx, subdictSecUserIdx );
		}
		subdictSecUserIdx.put( pkey, Buff );

		Map< CFSecSecSessionPKey, CFSecSecSessionBuff > subdictSecDevIdx;
		if( dictBySecDevIdx.containsKey( keySecDevIdx ) ) {
			subdictSecDevIdx = dictBySecDevIdx.get( keySecDevIdx );
		}
		else {
			subdictSecDevIdx = new HashMap< CFSecSecSessionPKey, CFSecSecSessionBuff >();
			dictBySecDevIdx.put( keySecDevIdx, subdictSecDevIdx );
		}
		subdictSecDevIdx.put( pkey, Buff );

		dictByStartIdx.put( keyStartIdx, Buff );

		Map< CFSecSecSessionPKey, CFSecSecSessionBuff > subdictFinishIdx;
		if( dictByFinishIdx.containsKey( keyFinishIdx ) ) {
			subdictFinishIdx = dictByFinishIdx.get( keyFinishIdx );
		}
		else {
			subdictFinishIdx = new HashMap< CFSecSecSessionPKey, CFSecSecSessionBuff >();
			dictByFinishIdx.put( keyFinishIdx, subdictFinishIdx );
		}
		subdictFinishIdx.put( pkey, Buff );

		Map< CFSecSecSessionPKey, CFSecSecSessionBuff > subdictSecProxyIdx;
		if( dictBySecProxyIdx.containsKey( keySecProxyIdx ) ) {
			subdictSecProxyIdx = dictBySecProxyIdx.get( keySecProxyIdx );
		}
		else {
			subdictSecProxyIdx = new HashMap< CFSecSecSessionPKey, CFSecSecSessionBuff >();
			dictBySecProxyIdx.put( keySecProxyIdx, subdictSecProxyIdx );
		}
		subdictSecProxyIdx.put( pkey, Buff );

	}

	public CFSecSecSessionBuff readDerived( CFSecAuthorization Authorization,
		CFSecSecSessionPKey PKey )
	{
		final String S_ProcName = "CFSecRamSecSession.readDerived";
		CFSecSecSessionPKey key = schema.getFactorySecSession().newPKey();
		key.setRequiredSecSessionId( PKey.getRequiredSecSessionId() );
		CFSecSecSessionBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecSecSessionBuff lockDerived( CFSecAuthorization Authorization,
		CFSecSecSessionPKey PKey )
	{
		final String S_ProcName = "CFSecRamSecSession.readDerived";
		CFSecSecSessionPKey key = schema.getFactorySecSession().newPKey();
		key.setRequiredSecSessionId( PKey.getRequiredSecSessionId() );
		CFSecSecSessionBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecSecSessionBuff[] readAllDerived( CFSecAuthorization Authorization ) {
		final String S_ProcName = "CFSecRamSecSession.readAllDerived";
		CFSecSecSessionBuff[] retList = new CFSecSecSessionBuff[ dictByPKey.values().size() ];
		Iterator< CFSecSecSessionBuff > iter = dictByPKey.values().iterator();
		int idx = 0;
		while( iter.hasNext() ) {
			retList[ idx++ ] = iter.next();
		}
		return( retList );
	}

	public CFSecSecSessionBuff[] readDerivedBySecUserIdx( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecUserId )
	{
		final String S_ProcName = "CFSecRamSecSession.readDerivedBySecUserIdx";
		CFSecSecSessionBySecUserIdxKey key = schema.getFactorySecSession().newSecUserIdxKey();
		key.setRequiredSecUserId( SecUserId );

		CFSecSecSessionBuff[] recArray;
		if( dictBySecUserIdx.containsKey( key ) ) {
			Map< CFSecSecSessionPKey, CFSecSecSessionBuff > subdictSecUserIdx
				= dictBySecUserIdx.get( key );
			recArray = new CFSecSecSessionBuff[ subdictSecUserIdx.size() ];
			Iterator< CFSecSecSessionBuff > iter = subdictSecUserIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFSecSecSessionPKey, CFSecSecSessionBuff > subdictSecUserIdx
				= new HashMap< CFSecSecSessionPKey, CFSecSecSessionBuff >();
			dictBySecUserIdx.put( key, subdictSecUserIdx );
			recArray = new CFSecSecSessionBuff[0];
		}
		return( recArray );
	}

	public CFSecSecSessionBuff[] readDerivedBySecDevIdx( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecUserId,
		String SecDevName )
	{
		final String S_ProcName = "CFSecRamSecSession.readDerivedBySecDevIdx";
		CFSecSecSessionBySecDevIdxKey key = schema.getFactorySecSession().newSecDevIdxKey();
		key.setRequiredSecUserId( SecUserId );
		key.setOptionalSecDevName( SecDevName );

		CFSecSecSessionBuff[] recArray;
		if( dictBySecDevIdx.containsKey( key ) ) {
			Map< CFSecSecSessionPKey, CFSecSecSessionBuff > subdictSecDevIdx
				= dictBySecDevIdx.get( key );
			recArray = new CFSecSecSessionBuff[ subdictSecDevIdx.size() ];
			Iterator< CFSecSecSessionBuff > iter = subdictSecDevIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFSecSecSessionPKey, CFSecSecSessionBuff > subdictSecDevIdx
				= new HashMap< CFSecSecSessionPKey, CFSecSecSessionBuff >();
			dictBySecDevIdx.put( key, subdictSecDevIdx );
			recArray = new CFSecSecSessionBuff[0];
		}
		return( recArray );
	}

	public CFSecSecSessionBuff readDerivedByStartIdx( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecUserId,
		LocalDateTime Start )
	{
		final String S_ProcName = "CFSecRamSecSession.readDerivedByStartIdx";
		CFSecSecSessionByStartIdxKey key = schema.getFactorySecSession().newStartIdxKey();
		key.setRequiredSecUserId( SecUserId );
		key.setRequiredStart( Start );

		CFSecSecSessionBuff buff;
		if( dictByStartIdx.containsKey( key ) ) {
			buff = dictByStartIdx.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecSecSessionBuff[] readDerivedByFinishIdx( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecUserId,
		LocalDateTime Finish )
	{
		final String S_ProcName = "CFSecRamSecSession.readDerivedByFinishIdx";
		CFSecSecSessionByFinishIdxKey key = schema.getFactorySecSession().newFinishIdxKey();
		key.setRequiredSecUserId( SecUserId );
		key.setOptionalFinish( Finish );

		CFSecSecSessionBuff[] recArray;
		if( dictByFinishIdx.containsKey( key ) ) {
			Map< CFSecSecSessionPKey, CFSecSecSessionBuff > subdictFinishIdx
				= dictByFinishIdx.get( key );
			recArray = new CFSecSecSessionBuff[ subdictFinishIdx.size() ];
			Iterator< CFSecSecSessionBuff > iter = subdictFinishIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFSecSecSessionPKey, CFSecSecSessionBuff > subdictFinishIdx
				= new HashMap< CFSecSecSessionPKey, CFSecSecSessionBuff >();
			dictByFinishIdx.put( key, subdictFinishIdx );
			recArray = new CFSecSecSessionBuff[0];
		}
		return( recArray );
	}

	public CFSecSecSessionBuff[] readDerivedBySecProxyIdx( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecProxyId )
	{
		final String S_ProcName = "CFSecRamSecSession.readDerivedBySecProxyIdx";
		CFSecSecSessionBySecProxyIdxKey key = schema.getFactorySecSession().newSecProxyIdxKey();
		key.setOptionalSecProxyId( SecProxyId );

		CFSecSecSessionBuff[] recArray;
		if( dictBySecProxyIdx.containsKey( key ) ) {
			Map< CFSecSecSessionPKey, CFSecSecSessionBuff > subdictSecProxyIdx
				= dictBySecProxyIdx.get( key );
			recArray = new CFSecSecSessionBuff[ subdictSecProxyIdx.size() ];
			Iterator< CFSecSecSessionBuff > iter = subdictSecProxyIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFSecSecSessionPKey, CFSecSecSessionBuff > subdictSecProxyIdx
				= new HashMap< CFSecSecSessionPKey, CFSecSecSessionBuff >();
			dictBySecProxyIdx.put( key, subdictSecProxyIdx );
			recArray = new CFSecSecSessionBuff[0];
		}
		return( recArray );
	}

	public CFSecSecSessionBuff readDerivedByIdIdx( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecSessionId )
	{
		final String S_ProcName = "CFSecRamSecSession.readDerivedByIdIdx() ";
		CFSecSecSessionPKey key = schema.getFactorySecSession().newPKey();
		key.setRequiredSecSessionId( SecSessionId );

		CFSecSecSessionBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecSecSessionBuff readBuff( CFSecAuthorization Authorization,
		CFSecSecSessionPKey PKey )
	{
		final String S_ProcName = "CFSecRamSecSession.readBuff";
		CFSecSecSessionBuff buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( ! buff.getClassCode().equals( "a010" ) ) ) {
			buff = null;
		}
		return( buff );
	}

	public CFSecSecSessionBuff lockBuff( CFSecAuthorization Authorization,
		CFSecSecSessionPKey PKey )
	{
		final String S_ProcName = "lockBuff";
		CFSecSecSessionBuff buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( ! buff.getClassCode().equals( "a010" ) ) ) {
			buff = null;
		}
		return( buff );
	}

	public CFSecSecSessionBuff[] readAllBuff( CFSecAuthorization Authorization )
	{
		final String S_ProcName = "CFSecRamSecSession.readAllBuff";
		CFSecSecSessionBuff buff;
		ArrayList<CFSecSecSessionBuff> filteredList = new ArrayList<CFSecSecSessionBuff>();
		CFSecSecSessionBuff[] buffList = readAllDerived( Authorization );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a010" ) ) {
				filteredList.add( buff );
			}
		}
		return( filteredList.toArray( new CFSecSecSessionBuff[0] ) );
	}

	/**
	 *	Read a page of all the specific SecSession buffer instances.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@return All the specific SecSession instances in the database accessible for the Authorization.
	 */
	public CFSecSecSessionBuff[] pageAllBuff( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 priorSecSessionId )
	{
		final String S_ProcName = "pageAllBuff";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	public CFSecSecSessionBuff readBuffByIdIdx( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecSessionId )
	{
		final String S_ProcName = "CFSecRamSecSession.readBuffByIdIdx() ";
		CFSecSecSessionBuff buff = readDerivedByIdIdx( Authorization,
			SecSessionId );
		if( ( buff != null ) && buff.getClassCode().equals( "a010" ) ) {
			return( (CFSecSecSessionBuff)buff );
		}
		else {
			return( null );
		}
	}

	public CFSecSecSessionBuff[] readBuffBySecUserIdx( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecUserId )
	{
		final String S_ProcName = "CFSecRamSecSession.readBuffBySecUserIdx() ";
		CFSecSecSessionBuff buff;
		ArrayList<CFSecSecSessionBuff> filteredList = new ArrayList<CFSecSecSessionBuff>();
		CFSecSecSessionBuff[] buffList = readDerivedBySecUserIdx( Authorization,
			SecUserId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a010" ) ) {
				filteredList.add( (CFSecSecSessionBuff)buff );
			}
		}
		return( filteredList.toArray( new CFSecSecSessionBuff[0] ) );
	}

	public CFSecSecSessionBuff[] readBuffBySecDevIdx( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecUserId,
		String SecDevName )
	{
		final String S_ProcName = "CFSecRamSecSession.readBuffBySecDevIdx() ";
		CFSecSecSessionBuff buff;
		ArrayList<CFSecSecSessionBuff> filteredList = new ArrayList<CFSecSecSessionBuff>();
		CFSecSecSessionBuff[] buffList = readDerivedBySecDevIdx( Authorization,
			SecUserId,
			SecDevName );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a010" ) ) {
				filteredList.add( (CFSecSecSessionBuff)buff );
			}
		}
		return( filteredList.toArray( new CFSecSecSessionBuff[0] ) );
	}

	public CFSecSecSessionBuff readBuffByStartIdx( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecUserId,
		LocalDateTime Start )
	{
		final String S_ProcName = "CFSecRamSecSession.readBuffByStartIdx() ";
		CFSecSecSessionBuff buff = readDerivedByStartIdx( Authorization,
			SecUserId,
			Start );
		if( ( buff != null ) && buff.getClassCode().equals( "a010" ) ) {
			return( (CFSecSecSessionBuff)buff );
		}
		else {
			return( null );
		}
	}

	public CFSecSecSessionBuff[] readBuffByFinishIdx( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecUserId,
		LocalDateTime Finish )
	{
		final String S_ProcName = "CFSecRamSecSession.readBuffByFinishIdx() ";
		CFSecSecSessionBuff buff;
		ArrayList<CFSecSecSessionBuff> filteredList = new ArrayList<CFSecSecSessionBuff>();
		CFSecSecSessionBuff[] buffList = readDerivedByFinishIdx( Authorization,
			SecUserId,
			Finish );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a010" ) ) {
				filteredList.add( (CFSecSecSessionBuff)buff );
			}
		}
		return( filteredList.toArray( new CFSecSecSessionBuff[0] ) );
	}

	public CFSecSecSessionBuff[] readBuffBySecProxyIdx( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecProxyId )
	{
		final String S_ProcName = "CFSecRamSecSession.readBuffBySecProxyIdx() ";
		CFSecSecSessionBuff buff;
		ArrayList<CFSecSecSessionBuff> filteredList = new ArrayList<CFSecSecSessionBuff>();
		CFSecSecSessionBuff[] buffList = readDerivedBySecProxyIdx( Authorization,
			SecProxyId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a010" ) ) {
				filteredList.add( (CFSecSecSessionBuff)buff );
			}
		}
		return( filteredList.toArray( new CFSecSecSessionBuff[0] ) );
	}

	/**
	 *	Read a page array of the specific SecSession buffer instances identified by the duplicate key SecUserIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	SecUserId	The SecSession key attribute of the instance generating the id.
	 *
	 *	@return An array of derived buffer instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	public CFSecSecSessionBuff[] pageBuffBySecUserIdx( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecUserId,
		CFLibDbKeyHash256 priorSecSessionId )
	{
		final String S_ProcName = "pageBuffBySecUserIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	/**
	 *	Read a page array of the specific SecSession buffer instances identified by the duplicate key SecDevIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	SecUserId	The SecSession key attribute of the instance generating the id.
	 *
	 *	@param	SecDevName	The SecSession key attribute of the instance generating the id.
	 *
	 *	@return An array of derived buffer instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	public CFSecSecSessionBuff[] pageBuffBySecDevIdx( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecUserId,
		String SecDevName,
		CFLibDbKeyHash256 priorSecSessionId )
	{
		final String S_ProcName = "pageBuffBySecDevIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	/**
	 *	Read a page array of the specific SecSession buffer instances identified by the duplicate key FinishIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	SecUserId	The SecSession key attribute of the instance generating the id.
	 *
	 *	@param	Finish	The SecSession key attribute of the instance generating the id.
	 *
	 *	@return An array of derived buffer instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	public CFSecSecSessionBuff[] pageBuffByFinishIdx( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecUserId,
		LocalDateTime Finish,
		CFLibDbKeyHash256 priorSecSessionId )
	{
		final String S_ProcName = "pageBuffByFinishIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	/**
	 *	Read a page array of the specific SecSession buffer instances identified by the duplicate key SecProxyIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	SecProxyId	The SecSession key attribute of the instance generating the id.
	 *
	 *	@return An array of derived buffer instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	public CFSecSecSessionBuff[] pageBuffBySecProxyIdx( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecProxyId,
		CFLibDbKeyHash256 priorSecSessionId )
	{
		final String S_ProcName = "pageBuffBySecProxyIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	public void updateSecSession( CFSecAuthorization Authorization,
		CFSecSecSessionBuff Buff )
	{
		CFSecSecSessionPKey pkey = schema.getFactorySecSession().newPKey();
		pkey.setRequiredSecSessionId( Buff.getRequiredSecSessionId() );
		CFSecSecSessionBuff existing = dictByPKey.get( pkey );
		if( existing == null ) {
			throw new CFLibStaleCacheDetectedException( getClass(),
				"updateSecSession",
				"Existing record not found",
				"SecSession",
				pkey );
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() ) {
			throw new CFLibCollisionDetectedException( getClass(),
				"updateSecSession",
				pkey );
		}
		Buff.setRequiredRevision( Buff.getRequiredRevision() + 1 );
		CFSecSecSessionBySecUserIdxKey existingKeySecUserIdx = schema.getFactorySecSession().newSecUserIdxKey();
		existingKeySecUserIdx.setRequiredSecUserId( existing.getRequiredSecUserId() );

		CFSecSecSessionBySecUserIdxKey newKeySecUserIdx = schema.getFactorySecSession().newSecUserIdxKey();
		newKeySecUserIdx.setRequiredSecUserId( Buff.getRequiredSecUserId() );

		CFSecSecSessionBySecDevIdxKey existingKeySecDevIdx = schema.getFactorySecSession().newSecDevIdxKey();
		existingKeySecDevIdx.setRequiredSecUserId( existing.getRequiredSecUserId() );
		existingKeySecDevIdx.setOptionalSecDevName( existing.getOptionalSecDevName() );

		CFSecSecSessionBySecDevIdxKey newKeySecDevIdx = schema.getFactorySecSession().newSecDevIdxKey();
		newKeySecDevIdx.setRequiredSecUserId( Buff.getRequiredSecUserId() );
		newKeySecDevIdx.setOptionalSecDevName( Buff.getOptionalSecDevName() );

		CFSecSecSessionByStartIdxKey existingKeyStartIdx = schema.getFactorySecSession().newStartIdxKey();
		existingKeyStartIdx.setRequiredSecUserId( existing.getRequiredSecUserId() );
		existingKeyStartIdx.setRequiredStart( existing.getRequiredStart() );

		CFSecSecSessionByStartIdxKey newKeyStartIdx = schema.getFactorySecSession().newStartIdxKey();
		newKeyStartIdx.setRequiredSecUserId( Buff.getRequiredSecUserId() );
		newKeyStartIdx.setRequiredStart( Buff.getRequiredStart() );

		CFSecSecSessionByFinishIdxKey existingKeyFinishIdx = schema.getFactorySecSession().newFinishIdxKey();
		existingKeyFinishIdx.setRequiredSecUserId( existing.getRequiredSecUserId() );
		existingKeyFinishIdx.setOptionalFinish( existing.getOptionalFinish() );

		CFSecSecSessionByFinishIdxKey newKeyFinishIdx = schema.getFactorySecSession().newFinishIdxKey();
		newKeyFinishIdx.setRequiredSecUserId( Buff.getRequiredSecUserId() );
		newKeyFinishIdx.setOptionalFinish( Buff.getOptionalFinish() );

		CFSecSecSessionBySecProxyIdxKey existingKeySecProxyIdx = schema.getFactorySecSession().newSecProxyIdxKey();
		existingKeySecProxyIdx.setOptionalSecProxyId( existing.getOptionalSecProxyId() );

		CFSecSecSessionBySecProxyIdxKey newKeySecProxyIdx = schema.getFactorySecSession().newSecProxyIdxKey();
		newKeySecProxyIdx.setOptionalSecProxyId( Buff.getOptionalSecProxyId() );

		// Check unique indexes

		if( ! existingKeyStartIdx.equals( newKeyStartIdx ) ) {
			if( dictByStartIdx.containsKey( newKeyStartIdx ) ) {
				throw new CFLibUniqueIndexViolationException( getClass(),
					"updateSecSession",
					"SessionStartIdx",
					newKeyStartIdx );
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
						"updateSecSession",
						"Container",
						"SecSessionSecUser",
						"SecUser",
						null );
				}
			}
		}

		// Update is valid

		Map< CFSecSecSessionPKey, CFSecSecSessionBuff > subdict;

		dictByPKey.remove( pkey );
		dictByPKey.put( pkey, Buff );

		subdict = dictBySecUserIdx.get( existingKeySecUserIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictBySecUserIdx.containsKey( newKeySecUserIdx ) ) {
			subdict = dictBySecUserIdx.get( newKeySecUserIdx );
		}
		else {
			subdict = new HashMap< CFSecSecSessionPKey, CFSecSecSessionBuff >();
			dictBySecUserIdx.put( newKeySecUserIdx, subdict );
		}
		subdict.put( pkey, Buff );

		subdict = dictBySecDevIdx.get( existingKeySecDevIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictBySecDevIdx.containsKey( newKeySecDevIdx ) ) {
			subdict = dictBySecDevIdx.get( newKeySecDevIdx );
		}
		else {
			subdict = new HashMap< CFSecSecSessionPKey, CFSecSecSessionBuff >();
			dictBySecDevIdx.put( newKeySecDevIdx, subdict );
		}
		subdict.put( pkey, Buff );

		dictByStartIdx.remove( existingKeyStartIdx );
		dictByStartIdx.put( newKeyStartIdx, Buff );

		subdict = dictByFinishIdx.get( existingKeyFinishIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictByFinishIdx.containsKey( newKeyFinishIdx ) ) {
			subdict = dictByFinishIdx.get( newKeyFinishIdx );
		}
		else {
			subdict = new HashMap< CFSecSecSessionPKey, CFSecSecSessionBuff >();
			dictByFinishIdx.put( newKeyFinishIdx, subdict );
		}
		subdict.put( pkey, Buff );

		subdict = dictBySecProxyIdx.get( existingKeySecProxyIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictBySecProxyIdx.containsKey( newKeySecProxyIdx ) ) {
			subdict = dictBySecProxyIdx.get( newKeySecProxyIdx );
		}
		else {
			subdict = new HashMap< CFSecSecSessionPKey, CFSecSecSessionBuff >();
			dictBySecProxyIdx.put( newKeySecProxyIdx, subdict );
		}
		subdict.put( pkey, Buff );

	}

	public void deleteSecSession( CFSecAuthorization Authorization,
		CFSecSecSessionBuff Buff )
	{
		final String S_ProcName = "CFSecRamSecSessionTable.deleteSecSession() ";
		String classCode;
		CFSecSecSessionPKey pkey = schema.getFactorySecSession().newPKey();
		pkey.setRequiredSecSessionId( Buff.getRequiredSecSessionId() );
		CFSecSecSessionBuff existing = dictByPKey.get( pkey );
		if( existing == null ) {
			return;
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() )
		{
			throw new CFLibCollisionDetectedException( getClass(),
				"deleteSecSession",
				pkey );
		}
		CFSecSecSessionBySecUserIdxKey keySecUserIdx = schema.getFactorySecSession().newSecUserIdxKey();
		keySecUserIdx.setRequiredSecUserId( existing.getRequiredSecUserId() );

		CFSecSecSessionBySecDevIdxKey keySecDevIdx = schema.getFactorySecSession().newSecDevIdxKey();
		keySecDevIdx.setRequiredSecUserId( existing.getRequiredSecUserId() );
		keySecDevIdx.setOptionalSecDevName( existing.getOptionalSecDevName() );

		CFSecSecSessionByStartIdxKey keyStartIdx = schema.getFactorySecSession().newStartIdxKey();
		keyStartIdx.setRequiredSecUserId( existing.getRequiredSecUserId() );
		keyStartIdx.setRequiredStart( existing.getRequiredStart() );

		CFSecSecSessionByFinishIdxKey keyFinishIdx = schema.getFactorySecSession().newFinishIdxKey();
		keyFinishIdx.setRequiredSecUserId( existing.getRequiredSecUserId() );
		keyFinishIdx.setOptionalFinish( existing.getOptionalFinish() );

		CFSecSecSessionBySecProxyIdxKey keySecProxyIdx = schema.getFactorySecSession().newSecProxyIdxKey();
		keySecProxyIdx.setOptionalSecProxyId( existing.getOptionalSecProxyId() );

		// Validate reverse foreign keys

		// Delete is valid
		Map< CFSecSecSessionPKey, CFSecSecSessionBuff > subdict;

		dictByPKey.remove( pkey );

		subdict = dictBySecUserIdx.get( keySecUserIdx );
		subdict.remove( pkey );

		subdict = dictBySecDevIdx.get( keySecDevIdx );
		subdict.remove( pkey );

		dictByStartIdx.remove( keyStartIdx );

		subdict = dictByFinishIdx.get( keyFinishIdx );
		subdict.remove( pkey );

		subdict = dictBySecProxyIdx.get( keySecProxyIdx );
		subdict.remove( pkey );

	}
	public void deleteSecSessionByIdIdx( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 argSecSessionId )
	{
		CFSecSecSessionPKey key = schema.getFactorySecSession().newPKey();
		key.setRequiredSecSessionId( argSecSessionId );
		deleteSecSessionByIdIdx( Authorization, key );
	}

	public void deleteSecSessionByIdIdx( CFSecAuthorization Authorization,
		CFSecSecSessionPKey argKey )
	{
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		CFSecSecSessionBuff cur;
		LinkedList<CFSecSecSessionBuff> matchSet = new LinkedList<CFSecSecSessionBuff>();
		Iterator<CFSecSecSessionBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecSecSessionBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableSecSession().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecSessionId() );
			deleteSecSession( Authorization, cur );
		}
	}

	public void deleteSecSessionBySecUserIdx( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 argSecUserId )
	{
		CFSecSecSessionBySecUserIdxKey key = schema.getFactorySecSession().newSecUserIdxKey();
		key.setRequiredSecUserId( argSecUserId );
		deleteSecSessionBySecUserIdx( Authorization, key );
	}

	public void deleteSecSessionBySecUserIdx( CFSecAuthorization Authorization,
		CFSecSecSessionBySecUserIdxKey argKey )
	{
		CFSecSecSessionBuff cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecSecSessionBuff> matchSet = new LinkedList<CFSecSecSessionBuff>();
		Iterator<CFSecSecSessionBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecSecSessionBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableSecSession().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecSessionId() );
			deleteSecSession( Authorization, cur );
		}
	}

	public void deleteSecSessionBySecDevIdx( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 argSecUserId,
		String argSecDevName )
	{
		CFSecSecSessionBySecDevIdxKey key = schema.getFactorySecSession().newSecDevIdxKey();
		key.setRequiredSecUserId( argSecUserId );
		key.setOptionalSecDevName( argSecDevName );
		deleteSecSessionBySecDevIdx( Authorization, key );
	}

	public void deleteSecSessionBySecDevIdx( CFSecAuthorization Authorization,
		CFSecSecSessionBySecDevIdxKey argKey )
	{
		CFSecSecSessionBuff cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( argKey.getOptionalSecDevName() != null ) {
			anyNotNull = true;
		}
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecSecSessionBuff> matchSet = new LinkedList<CFSecSecSessionBuff>();
		Iterator<CFSecSecSessionBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecSecSessionBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableSecSession().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecSessionId() );
			deleteSecSession( Authorization, cur );
		}
	}

	public void deleteSecSessionByStartIdx( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 argSecUserId,
		LocalDateTime argStart )
	{
		CFSecSecSessionByStartIdxKey key = schema.getFactorySecSession().newStartIdxKey();
		key.setRequiredSecUserId( argSecUserId );
		key.setRequiredStart( argStart );
		deleteSecSessionByStartIdx( Authorization, key );
	}

	public void deleteSecSessionByStartIdx( CFSecAuthorization Authorization,
		CFSecSecSessionByStartIdxKey argKey )
	{
		CFSecSecSessionBuff cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecSecSessionBuff> matchSet = new LinkedList<CFSecSecSessionBuff>();
		Iterator<CFSecSecSessionBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecSecSessionBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableSecSession().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecSessionId() );
			deleteSecSession( Authorization, cur );
		}
	}

	public void deleteSecSessionByFinishIdx( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 argSecUserId,
		LocalDateTime argFinish )
	{
		CFSecSecSessionByFinishIdxKey key = schema.getFactorySecSession().newFinishIdxKey();
		key.setRequiredSecUserId( argSecUserId );
		key.setOptionalFinish( argFinish );
		deleteSecSessionByFinishIdx( Authorization, key );
	}

	public void deleteSecSessionByFinishIdx( CFSecAuthorization Authorization,
		CFSecSecSessionByFinishIdxKey argKey )
	{
		CFSecSecSessionBuff cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( argKey.getOptionalFinish() != null ) {
			anyNotNull = true;
		}
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecSecSessionBuff> matchSet = new LinkedList<CFSecSecSessionBuff>();
		Iterator<CFSecSecSessionBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecSecSessionBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableSecSession().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecSessionId() );
			deleteSecSession( Authorization, cur );
		}
	}

	public void deleteSecSessionBySecProxyIdx( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 argSecProxyId )
	{
		CFSecSecSessionBySecProxyIdxKey key = schema.getFactorySecSession().newSecProxyIdxKey();
		key.setOptionalSecProxyId( argSecProxyId );
		deleteSecSessionBySecProxyIdx( Authorization, key );
	}

	public void deleteSecSessionBySecProxyIdx( CFSecAuthorization Authorization,
		CFSecSecSessionBySecProxyIdxKey argKey )
	{
		CFSecSecSessionBuff cur;
		boolean anyNotNull = false;
		if( argKey.getOptionalSecProxyId() != null ) {
			anyNotNull = true;
		}
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecSecSessionBuff> matchSet = new LinkedList<CFSecSecSessionBuff>();
		Iterator<CFSecSecSessionBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecSecSessionBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableSecSession().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecSessionId() );
			deleteSecSession( Authorization, cur );
		}
	}
}
