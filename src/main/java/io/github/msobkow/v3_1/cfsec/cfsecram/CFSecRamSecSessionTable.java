
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
import java.time.*;
import java.util.*;
import org.apache.commons.codec.binary.Base64;
import io.github.msobkow.v3_1.cflib.*;
import io.github.msobkow.v3_1.cflib.dbutil.*;

import io.github.msobkow.v3_1.cfsec.cfsec.*;
import io.github.msobkow.v3_1.cfsec.cfsec.buff.*;
import io.github.msobkow.v3_1.cfsec.cfsecobj.*;

/*
 *	CFSecRamSecSessionTable in-memory RAM DbIO implementation
 *	for SecSession.
 */
public class CFSecRamSecSessionTable
	implements ICFSecSecSessionTable
{
	private ICFSecSchema schema;
	private Map< CFLibDbKeyHash256,
				CFSecBuffSecSession > dictByPKey
		= new HashMap< CFLibDbKeyHash256,
				CFSecBuffSecSession >();
	private Map< CFSecBuffSecSessionBySecUserIdxKey,
				Map< CFLibDbKeyHash256,
					CFSecBuffSecSession >> dictBySecUserIdx
		= new HashMap< CFSecBuffSecSessionBySecUserIdxKey,
				Map< CFLibDbKeyHash256,
					CFSecBuffSecSession >>();
	private Map< CFSecBuffSecSessionBySecDevIdxKey,
				Map< CFLibDbKeyHash256,
					CFSecBuffSecSession >> dictBySecDevIdx
		= new HashMap< CFSecBuffSecSessionBySecDevIdxKey,
				Map< CFLibDbKeyHash256,
					CFSecBuffSecSession >>();
	private Map< CFSecBuffSecSessionByStartIdxKey,
			CFSecBuffSecSession > dictByStartIdx
		= new HashMap< CFSecBuffSecSessionByStartIdxKey,
			CFSecBuffSecSession >();
	private Map< CFSecBuffSecSessionByFinishIdxKey,
				Map< CFLibDbKeyHash256,
					CFSecBuffSecSession >> dictByFinishIdx
		= new HashMap< CFSecBuffSecSessionByFinishIdxKey,
				Map< CFLibDbKeyHash256,
					CFSecBuffSecSession >>();
	private Map< CFSecBuffSecSessionBySecProxyIdxKey,
				Map< CFLibDbKeyHash256,
					CFSecBuffSecSession >> dictBySecProxyIdx
		= new HashMap< CFSecBuffSecSessionBySecProxyIdxKey,
				Map< CFLibDbKeyHash256,
					CFSecBuffSecSession >>();

	public CFSecRamSecSessionTable( ICFSecSchema argSchema ) {
		schema = argSchema;
	}

	public void createSecSession( ICFSecAuthorization Authorization,
		ICFSecSecSession Buff )
	{
		final String S_ProcName = "createSecSession";
		CFLibDbKeyHash256 pkey = schema.getFactorySecSession().newPKey();
		pkey.setRequiredSecSessionId( schema.nextSecSessionIdGen() );
		Buff.setRequiredSecSessionId( pkey.getRequiredSecSessionId() );
		CFSecBuffSecSessionBySecUserIdxKey keySecUserIdx = schema.getFactorySecSession().newSecUserIdxKey();
		keySecUserIdx.setRequiredSecUserId( Buff.getRequiredSecUserId() );

		CFSecBuffSecSessionBySecDevIdxKey keySecDevIdx = schema.getFactorySecSession().newSecDevIdxKey();
		keySecDevIdx.setRequiredSecUserId( Buff.getRequiredSecUserId() );
		keySecDevIdx.setOptionalSecDevName( Buff.getOptionalSecDevName() );

		CFSecBuffSecSessionByStartIdxKey keyStartIdx = schema.getFactorySecSession().newStartIdxKey();
		keyStartIdx.setRequiredSecUserId( Buff.getRequiredSecUserId() );
		keyStartIdx.setRequiredStart( Buff.getRequiredStart() );

		CFSecBuffSecSessionByFinishIdxKey keyFinishIdx = schema.getFactorySecSession().newFinishIdxKey();
		keyFinishIdx.setRequiredSecUserId( Buff.getRequiredSecUserId() );
		keyFinishIdx.setOptionalFinish( Buff.getOptionalFinish() );

		CFSecBuffSecSessionBySecProxyIdxKey keySecProxyIdx = schema.getFactorySecSession().newSecProxyIdxKey();
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

		Map< CFLibDbKeyHash256, CFSecBuffSecSession > subdictSecUserIdx;
		if( dictBySecUserIdx.containsKey( keySecUserIdx ) ) {
			subdictSecUserIdx = dictBySecUserIdx.get( keySecUserIdx );
		}
		else {
			subdictSecUserIdx = new HashMap< CFLibDbKeyHash256, CFSecBuffSecSession >();
			dictBySecUserIdx.put( keySecUserIdx, subdictSecUserIdx );
		}
		subdictSecUserIdx.put( pkey, Buff );

		Map< CFLibDbKeyHash256, CFSecBuffSecSession > subdictSecDevIdx;
		if( dictBySecDevIdx.containsKey( keySecDevIdx ) ) {
			subdictSecDevIdx = dictBySecDevIdx.get( keySecDevIdx );
		}
		else {
			subdictSecDevIdx = new HashMap< CFLibDbKeyHash256, CFSecBuffSecSession >();
			dictBySecDevIdx.put( keySecDevIdx, subdictSecDevIdx );
		}
		subdictSecDevIdx.put( pkey, Buff );

		dictByStartIdx.put( keyStartIdx, Buff );

		Map< CFLibDbKeyHash256, CFSecBuffSecSession > subdictFinishIdx;
		if( dictByFinishIdx.containsKey( keyFinishIdx ) ) {
			subdictFinishIdx = dictByFinishIdx.get( keyFinishIdx );
		}
		else {
			subdictFinishIdx = new HashMap< CFLibDbKeyHash256, CFSecBuffSecSession >();
			dictByFinishIdx.put( keyFinishIdx, subdictFinishIdx );
		}
		subdictFinishIdx.put( pkey, Buff );

		Map< CFLibDbKeyHash256, CFSecBuffSecSession > subdictSecProxyIdx;
		if( dictBySecProxyIdx.containsKey( keySecProxyIdx ) ) {
			subdictSecProxyIdx = dictBySecProxyIdx.get( keySecProxyIdx );
		}
		else {
			subdictSecProxyIdx = new HashMap< CFLibDbKeyHash256, CFSecBuffSecSession >();
			dictBySecProxyIdx.put( keySecProxyIdx, subdictSecProxyIdx );
		}
		subdictSecProxyIdx.put( pkey, Buff );

	}

	public ICFSecSecSession readDerived( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 PKey )
	{
		final String S_ProcName = "CFSecRamSecSession.readDerived";
		ICFSecSecSession buff;
		if( dictByPKey.containsKey( PKey ) ) {
			buff = dictByPKey.get( PKey );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public ICFSecSecSession lockDerived( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 PKey )
	{
		final String S_ProcName = "CFSecRamSecSession.readDerived";
		CFLibDbKeyHash256 key = schema.getFactorySecSession().newPKey();
		key.setRequiredSecSessionId( PKey.getRequiredSecSessionId() );
		ICFSecSecSession buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public ICFSecSecSession[] readAllDerived( ICFSecAuthorization Authorization ) {
		final String S_ProcName = "CFSecRamSecSession.readAllDerived";
		ICFSecSecSession[] retList = new ICFSecSecSession[ dictByPKey.values().size() ];
		Iterator< ICFSecSecSession > iter = dictByPKey.values().iterator();
		int idx = 0;
		while( iter.hasNext() ) {
			retList[ idx++ ] = iter.next();
		}
		return( retList );
	}

	public ICFSecSecSession[] readDerivedBySecUserIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecUserId )
	{
		final String S_ProcName = "CFSecRamSecSession.readDerivedBySecUserIdx";
		CFSecBuffSecSessionBySecUserIdxKey key = schema.getFactorySecSession().newSecUserIdxKey();
		key.setRequiredSecUserId( SecUserId );

		ICFSecSecSession[] recArray;
		if( dictBySecUserIdx.containsKey( key ) ) {
			Map< CFLibDbKeyHash256, CFSecBuffSecSession > subdictSecUserIdx
				= dictBySecUserIdx.get( key );
			recArray = new ICFSecSecSession[ subdictSecUserIdx.size() ];
			Iterator< ICFSecSecSession > iter = subdictSecUserIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFLibDbKeyHash256, CFSecBuffSecSession > subdictSecUserIdx
				= new HashMap< CFLibDbKeyHash256, CFSecBuffSecSession >();
			dictBySecUserIdx.put( key, subdictSecUserIdx );
			recArray = new ICFSecSecSession[0];
		}
		return( recArray );
	}

	public ICFSecSecSession[] readDerivedBySecDevIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecUserId,
		String SecDevName )
	{
		final String S_ProcName = "CFSecRamSecSession.readDerivedBySecDevIdx";
		CFSecBuffSecSessionBySecDevIdxKey key = schema.getFactorySecSession().newSecDevIdxKey();
		key.setRequiredSecUserId( SecUserId );
		key.setOptionalSecDevName( SecDevName );

		ICFSecSecSession[] recArray;
		if( dictBySecDevIdx.containsKey( key ) ) {
			Map< CFLibDbKeyHash256, CFSecBuffSecSession > subdictSecDevIdx
				= dictBySecDevIdx.get( key );
			recArray = new ICFSecSecSession[ subdictSecDevIdx.size() ];
			Iterator< ICFSecSecSession > iter = subdictSecDevIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFLibDbKeyHash256, CFSecBuffSecSession > subdictSecDevIdx
				= new HashMap< CFLibDbKeyHash256, CFSecBuffSecSession >();
			dictBySecDevIdx.put( key, subdictSecDevIdx );
			recArray = new ICFSecSecSession[0];
		}
		return( recArray );
	}

	public ICFSecSecSession readDerivedByStartIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecUserId,
		LocalDateTime Start )
	{
		final String S_ProcName = "CFSecRamSecSession.readDerivedByStartIdx";
		CFSecBuffSecSessionByStartIdxKey key = schema.getFactorySecSession().newStartIdxKey();
		key.setRequiredSecUserId( SecUserId );
		key.setRequiredStart( Start );

		ICFSecSecSession buff;
		if( dictByStartIdx.containsKey( key ) ) {
			buff = dictByStartIdx.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public ICFSecSecSession[] readDerivedByFinishIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecUserId,
		LocalDateTime Finish )
	{
		final String S_ProcName = "CFSecRamSecSession.readDerivedByFinishIdx";
		CFSecBuffSecSessionByFinishIdxKey key = schema.getFactorySecSession().newFinishIdxKey();
		key.setRequiredSecUserId( SecUserId );
		key.setOptionalFinish( Finish );

		ICFSecSecSession[] recArray;
		if( dictByFinishIdx.containsKey( key ) ) {
			Map< CFLibDbKeyHash256, CFSecBuffSecSession > subdictFinishIdx
				= dictByFinishIdx.get( key );
			recArray = new ICFSecSecSession[ subdictFinishIdx.size() ];
			Iterator< ICFSecSecSession > iter = subdictFinishIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFLibDbKeyHash256, CFSecBuffSecSession > subdictFinishIdx
				= new HashMap< CFLibDbKeyHash256, CFSecBuffSecSession >();
			dictByFinishIdx.put( key, subdictFinishIdx );
			recArray = new ICFSecSecSession[0];
		}
		return( recArray );
	}

	public ICFSecSecSession[] readDerivedBySecProxyIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecProxyId )
	{
		final String S_ProcName = "CFSecRamSecSession.readDerivedBySecProxyIdx";
		CFSecBuffSecSessionBySecProxyIdxKey key = schema.getFactorySecSession().newSecProxyIdxKey();
		key.setOptionalSecProxyId( SecProxyId );

		ICFSecSecSession[] recArray;
		if( dictBySecProxyIdx.containsKey( key ) ) {
			Map< CFLibDbKeyHash256, CFSecBuffSecSession > subdictSecProxyIdx
				= dictBySecProxyIdx.get( key );
			recArray = new ICFSecSecSession[ subdictSecProxyIdx.size() ];
			Iterator< ICFSecSecSession > iter = subdictSecProxyIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFLibDbKeyHash256, CFSecBuffSecSession > subdictSecProxyIdx
				= new HashMap< CFLibDbKeyHash256, CFSecBuffSecSession >();
			dictBySecProxyIdx.put( key, subdictSecProxyIdx );
			recArray = new ICFSecSecSession[0];
		}
		return( recArray );
	}

	public ICFSecSecSession readDerivedByIdIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecSessionId )
	{
		final String S_ProcName = "CFSecRamSecSession.readDerivedByIdIdx() ";
		CFLibDbKeyHash256 key = schema.getFactorySecSession().newPKey();
		key.setRequiredSecSessionId( SecSessionId );

		ICFSecSecSession buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public ICFSecSecSession readBuff( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 PKey )
	{
		final String S_ProcName = "CFSecRamSecSession.readBuff";
		ICFSecSecSession buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( ! buff.getClassCode().equals( "a010" ) ) ) {
			buff = null;
		}
		return( buff );
	}

	public ICFSecSecSession lockBuff( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 PKey )
	{
		final String S_ProcName = "lockBuff";
		ICFSecSecSession buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( ! buff.getClassCode().equals( "a010" ) ) ) {
			buff = null;
		}
		return( buff );
	}

	public ICFSecSecSession[] readAllBuff( ICFSecAuthorization Authorization )
	{
		final String S_ProcName = "CFSecRamSecSession.readAllBuff";
		ICFSecSecSession buff;
		ArrayList<ICFSecSecSession> filteredList = new ArrayList<ICFSecSecSession>();
		ICFSecSecSession[] buffList = readAllDerived( Authorization );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a010" ) ) {
				filteredList.add( buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecSession[0] ) );
	}

	/**
	 *	Read a page of all the specific SecSession buffer instances.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@return All the specific SecSession instances in the database accessible for the Authorization.
	 */
	public ICFSecSecSession[] pageAllBuff( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 priorSecSessionId )
	{
		final String S_ProcName = "pageAllBuff";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	public ICFSecSecSession readBuffByIdIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecSessionId )
	{
		final String S_ProcName = "CFSecRamSecSession.readBuffByIdIdx() ";
		ICFSecSecSession buff = readDerivedByIdIdx( Authorization,
			SecSessionId );
		if( ( buff != null ) && buff.getClassCode().equals( "a010" ) ) {
			return( (ICFSecSecSession)buff );
		}
		else {
			return( null );
		}
	}

	public ICFSecSecSession[] readBuffBySecUserIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecUserId )
	{
		final String S_ProcName = "CFSecRamSecSession.readBuffBySecUserIdx() ";
		ICFSecSecSession buff;
		ArrayList<ICFSecSecSession> filteredList = new ArrayList<ICFSecSecSession>();
		ICFSecSecSession[] buffList = readDerivedBySecUserIdx( Authorization,
			SecUserId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a010" ) ) {
				filteredList.add( (ICFSecSecSession)buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecSession[0] ) );
	}

	public ICFSecSecSession[] readBuffBySecDevIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecUserId,
		String SecDevName )
	{
		final String S_ProcName = "CFSecRamSecSession.readBuffBySecDevIdx() ";
		ICFSecSecSession buff;
		ArrayList<ICFSecSecSession> filteredList = new ArrayList<ICFSecSecSession>();
		ICFSecSecSession[] buffList = readDerivedBySecDevIdx( Authorization,
			SecUserId,
			SecDevName );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a010" ) ) {
				filteredList.add( (ICFSecSecSession)buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecSession[0] ) );
	}

	public ICFSecSecSession readBuffByStartIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecUserId,
		LocalDateTime Start )
	{
		final String S_ProcName = "CFSecRamSecSession.readBuffByStartIdx() ";
		ICFSecSecSession buff = readDerivedByStartIdx( Authorization,
			SecUserId,
			Start );
		if( ( buff != null ) && buff.getClassCode().equals( "a010" ) ) {
			return( (ICFSecSecSession)buff );
		}
		else {
			return( null );
		}
	}

	public ICFSecSecSession[] readBuffByFinishIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecUserId,
		LocalDateTime Finish )
	{
		final String S_ProcName = "CFSecRamSecSession.readBuffByFinishIdx() ";
		ICFSecSecSession buff;
		ArrayList<ICFSecSecSession> filteredList = new ArrayList<ICFSecSecSession>();
		ICFSecSecSession[] buffList = readDerivedByFinishIdx( Authorization,
			SecUserId,
			Finish );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a010" ) ) {
				filteredList.add( (ICFSecSecSession)buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecSession[0] ) );
	}

	public ICFSecSecSession[] readBuffBySecProxyIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecProxyId )
	{
		final String S_ProcName = "CFSecRamSecSession.readBuffBySecProxyIdx() ";
		ICFSecSecSession buff;
		ArrayList<ICFSecSecSession> filteredList = new ArrayList<ICFSecSecSession>();
		ICFSecSecSession[] buffList = readDerivedBySecProxyIdx( Authorization,
			SecProxyId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a010" ) ) {
				filteredList.add( (ICFSecSecSession)buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecSession[0] ) );
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
	public ICFSecSecSession[] pageBuffBySecUserIdx( ICFSecAuthorization Authorization,
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
	public ICFSecSecSession[] pageBuffBySecDevIdx( ICFSecAuthorization Authorization,
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
	public ICFSecSecSession[] pageBuffByFinishIdx( ICFSecAuthorization Authorization,
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
	public ICFSecSecSession[] pageBuffBySecProxyIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecProxyId,
		CFLibDbKeyHash256 priorSecSessionId )
	{
		final String S_ProcName = "pageBuffBySecProxyIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	public void updateSecSession( ICFSecAuthorization Authorization,
		ICFSecSecSession Buff )
	{
		CFLibDbKeyHash256 pkey = schema.getFactorySecSession().newPKey();
		pkey.setRequiredSecSessionId( Buff.getRequiredSecSessionId() );
		ICFSecSecSession existing = dictByPKey.get( pkey );
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
		CFSecBuffSecSessionBySecUserIdxKey existingKeySecUserIdx = schema.getFactorySecSession().newSecUserIdxKey();
		existingKeySecUserIdx.setRequiredSecUserId( existing.getRequiredSecUserId() );

		CFSecBuffSecSessionBySecUserIdxKey newKeySecUserIdx = schema.getFactorySecSession().newSecUserIdxKey();
		newKeySecUserIdx.setRequiredSecUserId( Buff.getRequiredSecUserId() );

		CFSecBuffSecSessionBySecDevIdxKey existingKeySecDevIdx = schema.getFactorySecSession().newSecDevIdxKey();
		existingKeySecDevIdx.setRequiredSecUserId( existing.getRequiredSecUserId() );
		existingKeySecDevIdx.setOptionalSecDevName( existing.getOptionalSecDevName() );

		CFSecBuffSecSessionBySecDevIdxKey newKeySecDevIdx = schema.getFactorySecSession().newSecDevIdxKey();
		newKeySecDevIdx.setRequiredSecUserId( Buff.getRequiredSecUserId() );
		newKeySecDevIdx.setOptionalSecDevName( Buff.getOptionalSecDevName() );

		CFSecBuffSecSessionByStartIdxKey existingKeyStartIdx = schema.getFactorySecSession().newStartIdxKey();
		existingKeyStartIdx.setRequiredSecUserId( existing.getRequiredSecUserId() );
		existingKeyStartIdx.setRequiredStart( existing.getRequiredStart() );

		CFSecBuffSecSessionByStartIdxKey newKeyStartIdx = schema.getFactorySecSession().newStartIdxKey();
		newKeyStartIdx.setRequiredSecUserId( Buff.getRequiredSecUserId() );
		newKeyStartIdx.setRequiredStart( Buff.getRequiredStart() );

		CFSecBuffSecSessionByFinishIdxKey existingKeyFinishIdx = schema.getFactorySecSession().newFinishIdxKey();
		existingKeyFinishIdx.setRequiredSecUserId( existing.getRequiredSecUserId() );
		existingKeyFinishIdx.setOptionalFinish( existing.getOptionalFinish() );

		CFSecBuffSecSessionByFinishIdxKey newKeyFinishIdx = schema.getFactorySecSession().newFinishIdxKey();
		newKeyFinishIdx.setRequiredSecUserId( Buff.getRequiredSecUserId() );
		newKeyFinishIdx.setOptionalFinish( Buff.getOptionalFinish() );

		CFSecBuffSecSessionBySecProxyIdxKey existingKeySecProxyIdx = schema.getFactorySecSession().newSecProxyIdxKey();
		existingKeySecProxyIdx.setOptionalSecProxyId( existing.getOptionalSecProxyId() );

		CFSecBuffSecSessionBySecProxyIdxKey newKeySecProxyIdx = schema.getFactorySecSession().newSecProxyIdxKey();
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

		Map< CFLibDbKeyHash256, CFSecBuffSecSession > subdict;

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
			subdict = new HashMap< CFLibDbKeyHash256, CFSecBuffSecSession >();
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
			subdict = new HashMap< CFLibDbKeyHash256, CFSecBuffSecSession >();
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
			subdict = new HashMap< CFLibDbKeyHash256, CFSecBuffSecSession >();
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
			subdict = new HashMap< CFLibDbKeyHash256, CFSecBuffSecSession >();
			dictBySecProxyIdx.put( newKeySecProxyIdx, subdict );
		}
		subdict.put( pkey, Buff );

	}

	public void deleteSecSession( ICFSecAuthorization Authorization,
		ICFSecSecSession Buff )
	{
		final String S_ProcName = "CFSecRamSecSessionTable.deleteSecSession() ";
		String classCode;
		CFLibDbKeyHash256 pkey = schema.getFactorySecSession().newPKey();
		pkey.setRequiredSecSessionId( Buff.getRequiredSecSessionId() );
		ICFSecSecSession existing = dictByPKey.get( pkey );
		if( existing == null ) {
			return;
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() )
		{
			throw new CFLibCollisionDetectedException( getClass(),
				"deleteSecSession",
				pkey );
		}
		CFSecBuffSecSessionBySecUserIdxKey keySecUserIdx = schema.getFactorySecSession().newSecUserIdxKey();
		keySecUserIdx.setRequiredSecUserId( existing.getRequiredSecUserId() );

		CFSecBuffSecSessionBySecDevIdxKey keySecDevIdx = schema.getFactorySecSession().newSecDevIdxKey();
		keySecDevIdx.setRequiredSecUserId( existing.getRequiredSecUserId() );
		keySecDevIdx.setOptionalSecDevName( existing.getOptionalSecDevName() );

		CFSecBuffSecSessionByStartIdxKey keyStartIdx = schema.getFactorySecSession().newStartIdxKey();
		keyStartIdx.setRequiredSecUserId( existing.getRequiredSecUserId() );
		keyStartIdx.setRequiredStart( existing.getRequiredStart() );

		CFSecBuffSecSessionByFinishIdxKey keyFinishIdx = schema.getFactorySecSession().newFinishIdxKey();
		keyFinishIdx.setRequiredSecUserId( existing.getRequiredSecUserId() );
		keyFinishIdx.setOptionalFinish( existing.getOptionalFinish() );

		CFSecBuffSecSessionBySecProxyIdxKey keySecProxyIdx = schema.getFactorySecSession().newSecProxyIdxKey();
		keySecProxyIdx.setOptionalSecProxyId( existing.getOptionalSecProxyId() );

		// Validate reverse foreign keys

		// Delete is valid
		Map< CFLibDbKeyHash256, CFSecBuffSecSession > subdict;

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
	public void deleteSecSessionByIdIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argSecSessionId )
	{
		CFLibDbKeyHash256 key = schema.getFactorySecSession().newPKey();
		key.setRequiredSecSessionId( argSecSessionId );
		deleteSecSessionByIdIdx( Authorization, key );
	}

	public void deleteSecSessionByIdIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argKey )
	{
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		ICFSecSecSession cur;
		LinkedList<ICFSecSecSession> matchSet = new LinkedList<ICFSecSecSession>();
		Iterator<ICFSecSecSession> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<ICFSecSecSession> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableSecSession().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecSessionId() );
			deleteSecSession( Authorization, cur );
		}
	}

	public void deleteSecSessionBySecUserIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argSecUserId )
	{
		CFSecBuffSecSessionBySecUserIdxKey key = schema.getFactorySecSession().newSecUserIdxKey();
		key.setRequiredSecUserId( argSecUserId );
		deleteSecSessionBySecUserIdx( Authorization, key );
	}

	public void deleteSecSessionBySecUserIdx( ICFSecAuthorization Authorization,
		ICFSecSecSessionBySecUserIdxKey argKey )
	{
		ICFSecSecSession cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<ICFSecSecSession> matchSet = new LinkedList<ICFSecSecSession>();
		Iterator<ICFSecSecSession> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<ICFSecSecSession> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableSecSession().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecSessionId() );
			deleteSecSession( Authorization, cur );
		}
	}

	public void deleteSecSessionBySecDevIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argSecUserId,
		String argSecDevName )
	{
		CFSecBuffSecSessionBySecDevIdxKey key = schema.getFactorySecSession().newSecDevIdxKey();
		key.setRequiredSecUserId( argSecUserId );
		key.setOptionalSecDevName( argSecDevName );
		deleteSecSessionBySecDevIdx( Authorization, key );
	}

	public void deleteSecSessionBySecDevIdx( ICFSecAuthorization Authorization,
		ICFSecSecSessionBySecDevIdxKey argKey )
	{
		ICFSecSecSession cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( argKey.getOptionalSecDevName() != null ) {
			anyNotNull = true;
		}
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<ICFSecSecSession> matchSet = new LinkedList<ICFSecSecSession>();
		Iterator<ICFSecSecSession> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<ICFSecSecSession> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableSecSession().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecSessionId() );
			deleteSecSession( Authorization, cur );
		}
	}

	public void deleteSecSessionByStartIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argSecUserId,
		LocalDateTime argStart )
	{
		CFSecBuffSecSessionByStartIdxKey key = schema.getFactorySecSession().newStartIdxKey();
		key.setRequiredSecUserId( argSecUserId );
		key.setRequiredStart( argStart );
		deleteSecSessionByStartIdx( Authorization, key );
	}

	public void deleteSecSessionByStartIdx( ICFSecAuthorization Authorization,
		ICFSecSecSessionByStartIdxKey argKey )
	{
		ICFSecSecSession cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<ICFSecSecSession> matchSet = new LinkedList<ICFSecSecSession>();
		Iterator<ICFSecSecSession> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<ICFSecSecSession> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableSecSession().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecSessionId() );
			deleteSecSession( Authorization, cur );
		}
	}

	public void deleteSecSessionByFinishIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argSecUserId,
		LocalDateTime argFinish )
	{
		CFSecBuffSecSessionByFinishIdxKey key = schema.getFactorySecSession().newFinishIdxKey();
		key.setRequiredSecUserId( argSecUserId );
		key.setOptionalFinish( argFinish );
		deleteSecSessionByFinishIdx( Authorization, key );
	}

	public void deleteSecSessionByFinishIdx( ICFSecAuthorization Authorization,
		ICFSecSecSessionByFinishIdxKey argKey )
	{
		ICFSecSecSession cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( argKey.getOptionalFinish() != null ) {
			anyNotNull = true;
		}
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<ICFSecSecSession> matchSet = new LinkedList<ICFSecSecSession>();
		Iterator<ICFSecSecSession> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<ICFSecSecSession> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableSecSession().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecSessionId() );
			deleteSecSession( Authorization, cur );
		}
	}

	public void deleteSecSessionBySecProxyIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argSecProxyId )
	{
		CFSecBuffSecSessionBySecProxyIdxKey key = schema.getFactorySecSession().newSecProxyIdxKey();
		key.setOptionalSecProxyId( argSecProxyId );
		deleteSecSessionBySecProxyIdx( Authorization, key );
	}

	public void deleteSecSessionBySecProxyIdx( ICFSecAuthorization Authorization,
		ICFSecSecSessionBySecProxyIdxKey argKey )
	{
		ICFSecSecSession cur;
		boolean anyNotNull = false;
		if( argKey.getOptionalSecProxyId() != null ) {
			anyNotNull = true;
		}
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<ICFSecSecSession> matchSet = new LinkedList<ICFSecSecSession>();
		Iterator<ICFSecSecSession> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<ICFSecSecSession> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableSecSession().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecSessionId() );
			deleteSecSession( Authorization, cur );
		}
	}
}
