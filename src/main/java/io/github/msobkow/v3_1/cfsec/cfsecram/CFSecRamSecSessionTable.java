
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

	public CFSecBuffSecSession ensureRec(ICFSecSecSession rec) {
		if (rec == null) {
			return( null );
		}
		else {
			int classCode = rec.getClassCode();
			if (classCode == ICFSecSecSession.CLASS_CODE) {
				return( ((CFSecBuffSecSessionDefaultFactory)(schema.getFactorySecSession())).ensureRec((ICFSecSecSession)rec) );
			}
			else {
				throw new CFLibUnsupportedClassException(getClass(), "ensureRec", "rec", (Integer)classCode, "Classcode not recognized: " + Integer.toString(classCode));
			}
		}
	}

	public ICFSecSecSession createSecSession( ICFSecAuthorization Authorization,
		ICFSecSecSession iBuff )
	{
		final String S_ProcName = "createSecSession";
		
		CFSecBuffSecSession Buff = (CFSecBuffSecSession)ensureRec(iBuff);
		CFLibDbKeyHash256 pkey;
		pkey = schema.nextSecSessionIdGen();
		Buff.setRequiredSecSessionId( pkey );
		CFSecBuffSecSessionBySecUserIdxKey keySecUserIdx = (CFSecBuffSecSessionBySecUserIdxKey)schema.getFactorySecSession().newBySecUserIdxKey();
		keySecUserIdx.setRequiredSecUserId( Buff.getRequiredSecUserId() );

		CFSecBuffSecSessionBySecDevIdxKey keySecDevIdx = (CFSecBuffSecSessionBySecDevIdxKey)schema.getFactorySecSession().newBySecDevIdxKey();
		keySecDevIdx.setRequiredSecUserId( Buff.getRequiredSecUserId() );
		keySecDevIdx.setOptionalSecDevName( Buff.getOptionalSecDevName() );

		CFSecBuffSecSessionByStartIdxKey keyStartIdx = (CFSecBuffSecSessionByStartIdxKey)schema.getFactorySecSession().newByStartIdxKey();
		keyStartIdx.setRequiredSecUserId( Buff.getRequiredSecUserId() );
		keyStartIdx.setRequiredStart( Buff.getRequiredStart() );

		CFSecBuffSecSessionByFinishIdxKey keyFinishIdx = (CFSecBuffSecSessionByFinishIdxKey)schema.getFactorySecSession().newByFinishIdxKey();
		keyFinishIdx.setRequiredSecUserId( Buff.getRequiredSecUserId() );
		keyFinishIdx.setOptionalFinish( Buff.getOptionalFinish() );

		CFSecBuffSecSessionBySecProxyIdxKey keySecProxyIdx = (CFSecBuffSecSessionBySecProxyIdxKey)schema.getFactorySecSession().newBySecProxyIdxKey();
		keySecProxyIdx.setOptionalSecProxyId( Buff.getOptionalSecProxyId() );

		// Validate unique indexes

		if( dictByPKey.containsKey( pkey ) ) {
			throw new CFLibPrimaryKeyNotNewException( getClass(), S_ProcName, pkey );
		}

		if( dictByStartIdx.containsKey( keyStartIdx ) ) {
			throw new CFLibUniqueIndexViolationException( getClass(),
				S_ProcName,
				"SessionStartIdx",
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
						"Container",
						"SecSessionSecUser",
						"SecSessionSecUser",
						"SecUser",
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

		if (Buff == null) {
			return( null );
		}
		else {
			int classCode = Buff.getClassCode();
			if (classCode == ICFSecSecSession.CLASS_CODE) {
				CFSecBuffSecSession retbuff = ((CFSecBuffSecSession)(schema.getFactorySecSession().newRec()));
				retbuff.set(Buff);
				return( retbuff );
			}
			else {
				throw new CFLibUnsupportedClassException(getClass(), S_ProcName, "-create-buff-cloning-", (Integer)classCode, "Classcode not recognized: " + Integer.toString(classCode));
			}
		}
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
		final String S_ProcName = "CFSecRamSecSession.lockDerived";
		ICFSecSecSession buff;
		if( dictByPKey.containsKey( PKey ) ) {
			buff = dictByPKey.get( PKey );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public ICFSecSecSession[] readAllDerived( ICFSecAuthorization Authorization ) {
		final String S_ProcName = "CFSecRamSecSession.readAllDerived";
		ICFSecSecSession[] retList = new ICFSecSecSession[ dictByPKey.values().size() ];
		Iterator< CFSecBuffSecSession > iter = dictByPKey.values().iterator();
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
		CFSecBuffSecSessionBySecUserIdxKey key = (CFSecBuffSecSessionBySecUserIdxKey)schema.getFactorySecSession().newBySecUserIdxKey();

		key.setRequiredSecUserId( SecUserId );
		ICFSecSecSession[] recArray;
		if( dictBySecUserIdx.containsKey( key ) ) {
			Map< CFLibDbKeyHash256, CFSecBuffSecSession > subdictSecUserIdx
				= dictBySecUserIdx.get( key );
			recArray = new ICFSecSecSession[ subdictSecUserIdx.size() ];
			Iterator< CFSecBuffSecSession > iter = subdictSecUserIdx.values().iterator();
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
		CFSecBuffSecSessionBySecDevIdxKey key = (CFSecBuffSecSessionBySecDevIdxKey)schema.getFactorySecSession().newBySecDevIdxKey();

		key.setRequiredSecUserId( SecUserId );
		key.setOptionalSecDevName( SecDevName );
		ICFSecSecSession[] recArray;
		if( dictBySecDevIdx.containsKey( key ) ) {
			Map< CFLibDbKeyHash256, CFSecBuffSecSession > subdictSecDevIdx
				= dictBySecDevIdx.get( key );
			recArray = new ICFSecSecSession[ subdictSecDevIdx.size() ];
			Iterator< CFSecBuffSecSession > iter = subdictSecDevIdx.values().iterator();
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
		CFSecBuffSecSessionByStartIdxKey key = (CFSecBuffSecSessionByStartIdxKey)schema.getFactorySecSession().newByStartIdxKey();

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
		CFSecBuffSecSessionByFinishIdxKey key = (CFSecBuffSecSessionByFinishIdxKey)schema.getFactorySecSession().newByFinishIdxKey();

		key.setRequiredSecUserId( SecUserId );
		key.setOptionalFinish( Finish );
		ICFSecSecSession[] recArray;
		if( dictByFinishIdx.containsKey( key ) ) {
			Map< CFLibDbKeyHash256, CFSecBuffSecSession > subdictFinishIdx
				= dictByFinishIdx.get( key );
			recArray = new ICFSecSecSession[ subdictFinishIdx.size() ];
			Iterator< CFSecBuffSecSession > iter = subdictFinishIdx.values().iterator();
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
		CFSecBuffSecSessionBySecProxyIdxKey key = (CFSecBuffSecSessionBySecProxyIdxKey)schema.getFactorySecSession().newBySecProxyIdxKey();

		key.setOptionalSecProxyId( SecProxyId );
		ICFSecSecSession[] recArray;
		if( dictBySecProxyIdx.containsKey( key ) ) {
			Map< CFLibDbKeyHash256, CFSecBuffSecSession > subdictSecProxyIdx
				= dictBySecProxyIdx.get( key );
			recArray = new ICFSecSecSession[ subdictSecProxyIdx.size() ];
			Iterator< CFSecBuffSecSession > iter = subdictSecProxyIdx.values().iterator();
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
		ICFSecSecSession buff;
		if( dictByPKey.containsKey( SecSessionId ) ) {
			buff = dictByPKey.get( SecSessionId );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public ICFSecSecSession readRec( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 PKey )
	{
		final String S_ProcName = "CFSecRamSecSession.readRec";
		ICFSecSecSession buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecSecSession.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	public ICFSecSecSession lockRec( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 PKey )
	{
		final String S_ProcName = "lockRec";
		ICFSecSecSession buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecSecSession.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	public ICFSecSecSession[] readAllRec( ICFSecAuthorization Authorization )
	{
		final String S_ProcName = "CFSecRamSecSession.readAllRec";
		ICFSecSecSession buff;
		ArrayList<ICFSecSecSession> filteredList = new ArrayList<ICFSecSecSession>();
		ICFSecSecSession[] buffList = readAllDerived( Authorization );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecSession.CLASS_CODE ) ) {
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
	public ICFSecSecSession[] pageAllRec( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 priorSecSessionId )
	{
		final String S_ProcName = "pageAllRec";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	public ICFSecSecSession readRecByIdIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecSessionId )
	{
		final String S_ProcName = "CFSecRamSecSession.readRecByIdIdx() ";
		ICFSecSecSession buff = readDerivedByIdIdx( Authorization,
			SecSessionId );
		if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecSession.CLASS_CODE ) ) {
			return( (ICFSecSecSession)buff );
		}
		else {
			return( null );
		}
	}

	public ICFSecSecSession[] readRecBySecUserIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecUserId )
	{
		final String S_ProcName = "CFSecRamSecSession.readRecBySecUserIdx() ";
		ICFSecSecSession buff;
		ArrayList<ICFSecSecSession> filteredList = new ArrayList<ICFSecSecSession>();
		ICFSecSecSession[] buffList = readDerivedBySecUserIdx( Authorization,
			SecUserId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecSession.CLASS_CODE ) ) {
				filteredList.add( (ICFSecSecSession)buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecSession[0] ) );
	}

	public ICFSecSecSession[] readRecBySecDevIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecUserId,
		String SecDevName )
	{
		final String S_ProcName = "CFSecRamSecSession.readRecBySecDevIdx() ";
		ICFSecSecSession buff;
		ArrayList<ICFSecSecSession> filteredList = new ArrayList<ICFSecSecSession>();
		ICFSecSecSession[] buffList = readDerivedBySecDevIdx( Authorization,
			SecUserId,
			SecDevName );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecSession.CLASS_CODE ) ) {
				filteredList.add( (ICFSecSecSession)buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecSession[0] ) );
	}

	public ICFSecSecSession readRecByStartIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecUserId,
		LocalDateTime Start )
	{
		final String S_ProcName = "CFSecRamSecSession.readRecByStartIdx() ";
		ICFSecSecSession buff = readDerivedByStartIdx( Authorization,
			SecUserId,
			Start );
		if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecSession.CLASS_CODE ) ) {
			return( (ICFSecSecSession)buff );
		}
		else {
			return( null );
		}
	}

	public ICFSecSecSession[] readRecByFinishIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecUserId,
		LocalDateTime Finish )
	{
		final String S_ProcName = "CFSecRamSecSession.readRecByFinishIdx() ";
		ICFSecSecSession buff;
		ArrayList<ICFSecSecSession> filteredList = new ArrayList<ICFSecSecSession>();
		ICFSecSecSession[] buffList = readDerivedByFinishIdx( Authorization,
			SecUserId,
			Finish );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecSession.CLASS_CODE ) ) {
				filteredList.add( (ICFSecSecSession)buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecSession[0] ) );
	}

	public ICFSecSecSession[] readRecBySecProxyIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecProxyId )
	{
		final String S_ProcName = "CFSecRamSecSession.readRecBySecProxyIdx() ";
		ICFSecSecSession buff;
		ArrayList<ICFSecSecSession> filteredList = new ArrayList<ICFSecSecSession>();
		ICFSecSecSession[] buffList = readDerivedBySecProxyIdx( Authorization,
			SecProxyId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecSession.CLASS_CODE ) ) {
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
	public ICFSecSecSession[] pageRecBySecUserIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecUserId,
		CFLibDbKeyHash256 priorSecSessionId )
	{
		final String S_ProcName = "pageRecBySecUserIdx";
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
	public ICFSecSecSession[] pageRecBySecDevIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecUserId,
		String SecDevName,
		CFLibDbKeyHash256 priorSecSessionId )
	{
		final String S_ProcName = "pageRecBySecDevIdx";
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
	public ICFSecSecSession[] pageRecByFinishIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecUserId,
		LocalDateTime Finish,
		CFLibDbKeyHash256 priorSecSessionId )
	{
		final String S_ProcName = "pageRecByFinishIdx";
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
	public ICFSecSecSession[] pageRecBySecProxyIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecProxyId,
		CFLibDbKeyHash256 priorSecSessionId )
	{
		final String S_ProcName = "pageRecBySecProxyIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	public ICFSecSecSession updateSecSession( ICFSecAuthorization Authorization,
		ICFSecSecSession iBuff )
	{
		CFSecBuffSecSession Buff = (CFSecBuffSecSession)ensureRec(iBuff);
		CFLibDbKeyHash256 pkey = Buff.getPKey();
		CFSecBuffSecSession existing = dictByPKey.get( pkey );
		if( existing == null ) {
			throw new CFLibStaleCacheDetectedException( getClass(),
				"updateSecSession",
				"Existing record not found",
				"Existing record not found",
				"SecSession",
				"SecSession",
				pkey );
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() ) {
			throw new CFLibCollisionDetectedException( getClass(),
				"updateSecSession",
				pkey );
		}
		Buff.setRequiredRevision( Buff.getRequiredRevision() + 1 );
		CFSecBuffSecSessionBySecUserIdxKey existingKeySecUserIdx = (CFSecBuffSecSessionBySecUserIdxKey)schema.getFactorySecSession().newBySecUserIdxKey();
		existingKeySecUserIdx.setRequiredSecUserId( existing.getRequiredSecUserId() );

		CFSecBuffSecSessionBySecUserIdxKey newKeySecUserIdx = (CFSecBuffSecSessionBySecUserIdxKey)schema.getFactorySecSession().newBySecUserIdxKey();
		newKeySecUserIdx.setRequiredSecUserId( Buff.getRequiredSecUserId() );

		CFSecBuffSecSessionBySecDevIdxKey existingKeySecDevIdx = (CFSecBuffSecSessionBySecDevIdxKey)schema.getFactorySecSession().newBySecDevIdxKey();
		existingKeySecDevIdx.setRequiredSecUserId( existing.getRequiredSecUserId() );
		existingKeySecDevIdx.setOptionalSecDevName( existing.getOptionalSecDevName() );

		CFSecBuffSecSessionBySecDevIdxKey newKeySecDevIdx = (CFSecBuffSecSessionBySecDevIdxKey)schema.getFactorySecSession().newBySecDevIdxKey();
		newKeySecDevIdx.setRequiredSecUserId( Buff.getRequiredSecUserId() );
		newKeySecDevIdx.setOptionalSecDevName( Buff.getOptionalSecDevName() );

		CFSecBuffSecSessionByStartIdxKey existingKeyStartIdx = (CFSecBuffSecSessionByStartIdxKey)schema.getFactorySecSession().newByStartIdxKey();
		existingKeyStartIdx.setRequiredSecUserId( existing.getRequiredSecUserId() );
		existingKeyStartIdx.setRequiredStart( existing.getRequiredStart() );

		CFSecBuffSecSessionByStartIdxKey newKeyStartIdx = (CFSecBuffSecSessionByStartIdxKey)schema.getFactorySecSession().newByStartIdxKey();
		newKeyStartIdx.setRequiredSecUserId( Buff.getRequiredSecUserId() );
		newKeyStartIdx.setRequiredStart( Buff.getRequiredStart() );

		CFSecBuffSecSessionByFinishIdxKey existingKeyFinishIdx = (CFSecBuffSecSessionByFinishIdxKey)schema.getFactorySecSession().newByFinishIdxKey();
		existingKeyFinishIdx.setRequiredSecUserId( existing.getRequiredSecUserId() );
		existingKeyFinishIdx.setOptionalFinish( existing.getOptionalFinish() );

		CFSecBuffSecSessionByFinishIdxKey newKeyFinishIdx = (CFSecBuffSecSessionByFinishIdxKey)schema.getFactorySecSession().newByFinishIdxKey();
		newKeyFinishIdx.setRequiredSecUserId( Buff.getRequiredSecUserId() );
		newKeyFinishIdx.setOptionalFinish( Buff.getOptionalFinish() );

		CFSecBuffSecSessionBySecProxyIdxKey existingKeySecProxyIdx = (CFSecBuffSecSessionBySecProxyIdxKey)schema.getFactorySecSession().newBySecProxyIdxKey();
		existingKeySecProxyIdx.setOptionalSecProxyId( existing.getOptionalSecProxyId() );

		CFSecBuffSecSessionBySecProxyIdxKey newKeySecProxyIdx = (CFSecBuffSecSessionBySecProxyIdxKey)schema.getFactorySecSession().newBySecProxyIdxKey();
		newKeySecProxyIdx.setOptionalSecProxyId( Buff.getOptionalSecProxyId() );

		// Check unique indexes

		if( ! existingKeyStartIdx.equals( newKeyStartIdx ) ) {
			if( dictByStartIdx.containsKey( newKeyStartIdx ) ) {
				throw new CFLibUniqueIndexViolationException( getClass(),
					"updateSecSession",
					"SessionStartIdx",
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
						"Container",
						"SecSessionSecUser",
						"SecSessionSecUser",
						"SecUser",
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

		return(Buff);
	}

	public void deleteSecSession( ICFSecAuthorization Authorization,
		ICFSecSecSession iBuff )
	{
		final String S_ProcName = "CFSecRamSecSessionTable.deleteSecSession() ";
		CFSecBuffSecSession Buff = (CFSecBuffSecSession)ensureRec(iBuff);
		int classCode;
		CFLibDbKeyHash256 pkey = (CFLibDbKeyHash256)(Buff.getPKey());
		CFSecBuffSecSession existing = dictByPKey.get( pkey );
		if( existing == null ) {
			return;
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() )
		{
			throw new CFLibCollisionDetectedException( getClass(),
				"deleteSecSession",
				pkey );
		}
		CFSecBuffSecSessionBySecUserIdxKey keySecUserIdx = (CFSecBuffSecSessionBySecUserIdxKey)schema.getFactorySecSession().newBySecUserIdxKey();
		keySecUserIdx.setRequiredSecUserId( existing.getRequiredSecUserId() );

		CFSecBuffSecSessionBySecDevIdxKey keySecDevIdx = (CFSecBuffSecSessionBySecDevIdxKey)schema.getFactorySecSession().newBySecDevIdxKey();
		keySecDevIdx.setRequiredSecUserId( existing.getRequiredSecUserId() );
		keySecDevIdx.setOptionalSecDevName( existing.getOptionalSecDevName() );

		CFSecBuffSecSessionByStartIdxKey keyStartIdx = (CFSecBuffSecSessionByStartIdxKey)schema.getFactorySecSession().newByStartIdxKey();
		keyStartIdx.setRequiredSecUserId( existing.getRequiredSecUserId() );
		keyStartIdx.setRequiredStart( existing.getRequiredStart() );

		CFSecBuffSecSessionByFinishIdxKey keyFinishIdx = (CFSecBuffSecSessionByFinishIdxKey)schema.getFactorySecSession().newByFinishIdxKey();
		keyFinishIdx.setRequiredSecUserId( existing.getRequiredSecUserId() );
		keyFinishIdx.setOptionalFinish( existing.getOptionalFinish() );

		CFSecBuffSecSessionBySecProxyIdxKey keySecProxyIdx = (CFSecBuffSecSessionBySecProxyIdxKey)schema.getFactorySecSession().newBySecProxyIdxKey();
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
		CFLibDbKeyHash256 argKey )
	{
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		CFSecBuffSecSession cur;
		LinkedList<CFSecBuffSecSession> matchSet = new LinkedList<CFSecBuffSecSession>();
		Iterator<CFSecBuffSecSession> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecSession> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecSession)(schema.getTableSecSession().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecSessionId() ));
			deleteSecSession( Authorization, cur );
		}
	}

	public void deleteSecSessionBySecUserIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argSecUserId )
	{
		CFSecBuffSecSessionBySecUserIdxKey key = (CFSecBuffSecSessionBySecUserIdxKey)schema.getFactorySecSession().newBySecUserIdxKey();
		key.setRequiredSecUserId( argSecUserId );
		deleteSecSessionBySecUserIdx( Authorization, key );
	}

	public void deleteSecSessionBySecUserIdx( ICFSecAuthorization Authorization,
		ICFSecSecSessionBySecUserIdxKey argKey )
	{
		CFSecBuffSecSession cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffSecSession> matchSet = new LinkedList<CFSecBuffSecSession>();
		Iterator<CFSecBuffSecSession> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecSession> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecSession)(schema.getTableSecSession().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecSessionId() ));
			deleteSecSession( Authorization, cur );
		}
	}

	public void deleteSecSessionBySecDevIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argSecUserId,
		String argSecDevName )
	{
		CFSecBuffSecSessionBySecDevIdxKey key = (CFSecBuffSecSessionBySecDevIdxKey)schema.getFactorySecSession().newBySecDevIdxKey();
		key.setRequiredSecUserId( argSecUserId );
		key.setOptionalSecDevName( argSecDevName );
		deleteSecSessionBySecDevIdx( Authorization, key );
	}

	public void deleteSecSessionBySecDevIdx( ICFSecAuthorization Authorization,
		ICFSecSecSessionBySecDevIdxKey argKey )
	{
		CFSecBuffSecSession cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( argKey.getOptionalSecDevName() != null ) {
			anyNotNull = true;
		}
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffSecSession> matchSet = new LinkedList<CFSecBuffSecSession>();
		Iterator<CFSecBuffSecSession> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecSession> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecSession)(schema.getTableSecSession().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecSessionId() ));
			deleteSecSession( Authorization, cur );
		}
	}

	public void deleteSecSessionByStartIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argSecUserId,
		LocalDateTime argStart )
	{
		CFSecBuffSecSessionByStartIdxKey key = (CFSecBuffSecSessionByStartIdxKey)schema.getFactorySecSession().newByStartIdxKey();
		key.setRequiredSecUserId( argSecUserId );
		key.setRequiredStart( argStart );
		deleteSecSessionByStartIdx( Authorization, key );
	}

	public void deleteSecSessionByStartIdx( ICFSecAuthorization Authorization,
		ICFSecSecSessionByStartIdxKey argKey )
	{
		CFSecBuffSecSession cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffSecSession> matchSet = new LinkedList<CFSecBuffSecSession>();
		Iterator<CFSecBuffSecSession> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecSession> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecSession)(schema.getTableSecSession().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecSessionId() ));
			deleteSecSession( Authorization, cur );
		}
	}

	public void deleteSecSessionByFinishIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argSecUserId,
		LocalDateTime argFinish )
	{
		CFSecBuffSecSessionByFinishIdxKey key = (CFSecBuffSecSessionByFinishIdxKey)schema.getFactorySecSession().newByFinishIdxKey();
		key.setRequiredSecUserId( argSecUserId );
		key.setOptionalFinish( argFinish );
		deleteSecSessionByFinishIdx( Authorization, key );
	}

	public void deleteSecSessionByFinishIdx( ICFSecAuthorization Authorization,
		ICFSecSecSessionByFinishIdxKey argKey )
	{
		CFSecBuffSecSession cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( argKey.getOptionalFinish() != null ) {
			anyNotNull = true;
		}
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffSecSession> matchSet = new LinkedList<CFSecBuffSecSession>();
		Iterator<CFSecBuffSecSession> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecSession> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecSession)(schema.getTableSecSession().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecSessionId() ));
			deleteSecSession( Authorization, cur );
		}
	}

	public void deleteSecSessionBySecProxyIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argSecProxyId )
	{
		CFSecBuffSecSessionBySecProxyIdxKey key = (CFSecBuffSecSessionBySecProxyIdxKey)schema.getFactorySecSession().newBySecProxyIdxKey();
		key.setOptionalSecProxyId( argSecProxyId );
		deleteSecSessionBySecProxyIdx( Authorization, key );
	}

	public void deleteSecSessionBySecProxyIdx( ICFSecAuthorization Authorization,
		ICFSecSecSessionBySecProxyIdxKey argKey )
	{
		CFSecBuffSecSession cur;
		boolean anyNotNull = false;
		if( argKey.getOptionalSecProxyId() != null ) {
			anyNotNull = true;
		}
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffSecSession> matchSet = new LinkedList<CFSecBuffSecSession>();
		Iterator<CFSecBuffSecSession> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecSession> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecSession)(schema.getTableSecSession().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecSessionId() ));
			deleteSecSession( Authorization, cur );
		}
	}
}
