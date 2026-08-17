
// Description: Java 25 in-memory RAM DbIO implementation for SecSession.

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
 *	CFSecRamSecSessionTable in-memory RAM DbIO implementation
 *	for SecSession.
 */
public class CFSecRamSecSessionTable
	implements ICFSecSecSessionTable
{
	private ICFSecSchema schema;
	private Map< ICFLibKeyHash256,
				CFSecBuffSecSession > dictByPKey
		= new HashMap< ICFLibKeyHash256,
				CFSecBuffSecSession >();
	private Map< CFSecBuffSecSessionBySecUserIdxKey,
				Map< ICFLibKeyHash256,
					CFSecBuffSecSession >> dictBySecUserIdx
		= new HashMap< CFSecBuffSecSessionBySecUserIdxKey,
				Map< ICFLibKeyHash256,
					CFSecBuffSecSession >>();
	private Map< CFSecBuffSecSessionByStartIdxKey,
			CFSecBuffSecSession > dictByStartIdx
		= new HashMap< CFSecBuffSecSessionByStartIdxKey,
			CFSecBuffSecSession >();
	private Map< CFSecBuffSecSessionByFinishIdxKey,
				Map< ICFLibKeyHash256,
					CFSecBuffSecSession >> dictByFinishIdx
		= new HashMap< CFSecBuffSecSessionByFinishIdxKey,
				Map< ICFLibKeyHash256,
					CFSecBuffSecSession >>();
	private Map< CFSecBuffSecSessionBySecProxyIdxKey,
				Map< ICFLibKeyHash256,
					CFSecBuffSecSession >> dictBySecProxyIdx
		= new HashMap< CFSecBuffSecSessionBySecProxyIdxKey,
				Map< ICFLibKeyHash256,
					CFSecBuffSecSession >>();

	public CFSecRamSecSessionTable( ICFSecSchema argSchema ) {
		schema = argSchema;
	}

	public CFSecBuffSecSession ensureRec(ICFSecSecSession rec) {
		return (((CFSecBuffSecSessionFactoryService)(schema.getCFSecBuffFactory().getFactorySecSession())).ensureRec(rec));
	}

	@Override
	public ICFSecSecSession createSecSession( ICFSecAuthorization Authorization,
		ICFSecSecSession iBuff )
	{
		final String S_ProcName = "createSecSession";
		
		CFSecBuffSecSession Buff = (CFSecBuffSecSession)ensureRec(iBuff);
		ICFLibKeyHash256 pkey;
		pkey = schema.nextSecSessionIdGen();
		Buff.setRequiredSecSessionId( pkey );
		CFSecBuffSecSessionBySecUserIdxKey keySecUserIdx = (CFSecBuffSecSessionBySecUserIdxKey)schema.getCFSecBuffFactory().getFactorySecSession().newBySecUserIdxKey();
		keySecUserIdx.setRequiredSecUserId( Buff.getRequiredSecUserId() );

		CFSecBuffSecSessionByStartIdxKey keyStartIdx = (CFSecBuffSecSessionByStartIdxKey)schema.getCFSecBuffFactory().getFactorySecSession().newByStartIdxKey();
		keyStartIdx.setRequiredSecUserId( Buff.getRequiredSecUserId() );
		keyStartIdx.setRequiredStart( Buff.getRequiredStart() );

		CFSecBuffSecSessionByFinishIdxKey keyFinishIdx = (CFSecBuffSecSessionByFinishIdxKey)schema.getCFSecBuffFactory().getFactorySecSession().newByFinishIdxKey();
		keyFinishIdx.setRequiredSecUserId( Buff.getRequiredSecUserId() );
		keyFinishIdx.setOptionalFinish( Buff.getOptionalFinish() );

		CFSecBuffSecSessionBySecProxyIdxKey keySecProxyIdx = (CFSecBuffSecSessionBySecProxyIdxKey)schema.getCFSecBuffFactory().getFactorySecSession().newBySecProxyIdxKey();
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

		Map< ICFLibKeyHash256, CFSecBuffSecSession > subdictSecUserIdx;
		if( dictBySecUserIdx.containsKey( keySecUserIdx ) ) {
			subdictSecUserIdx = dictBySecUserIdx.get( keySecUserIdx );
		}
		else {
			subdictSecUserIdx = new HashMap< ICFLibKeyHash256, CFSecBuffSecSession >();
			dictBySecUserIdx.put( keySecUserIdx, subdictSecUserIdx );
		}
		subdictSecUserIdx.put( pkey, Buff );

		dictByStartIdx.put( keyStartIdx, Buff );

		Map< ICFLibKeyHash256, CFSecBuffSecSession > subdictFinishIdx;
		if( dictByFinishIdx.containsKey( keyFinishIdx ) ) {
			subdictFinishIdx = dictByFinishIdx.get( keyFinishIdx );
		}
		else {
			subdictFinishIdx = new HashMap< ICFLibKeyHash256, CFSecBuffSecSession >();
			dictByFinishIdx.put( keyFinishIdx, subdictFinishIdx );
		}
		subdictFinishIdx.put( pkey, Buff );

		Map< ICFLibKeyHash256, CFSecBuffSecSession > subdictSecProxyIdx;
		if( dictBySecProxyIdx.containsKey( keySecProxyIdx ) ) {
			subdictSecProxyIdx = dictBySecProxyIdx.get( keySecProxyIdx );
		}
		else {
			subdictSecProxyIdx = new HashMap< ICFLibKeyHash256, CFSecBuffSecSession >();
			dictBySecProxyIdx.put( keySecProxyIdx, subdictSecProxyIdx );
		}
		subdictSecProxyIdx.put( pkey, Buff );

		if (Buff == null) {
			return( null );
		}
		else {
			int classCode = Buff.getClassCode();
			if (classCode == ICFSecSecSession.CLASS_CODE) {
				CFSecBuffSecSession retbuff = ((CFSecBuffSecSession)(schema.getCFSecBuffFactory().getFactorySecSession().newRec()));
				retbuff.set(Buff);
				return( retbuff );
			}
			else {
				throw new CFLibUnsupportedClassException(getClass(), S_ProcName, "-create-buff-cloning-", (Integer)classCode, "Classcode not recognized: " + Integer.toString(classCode));
			}
		}
	}

	@Override
	public ICFSecSecSession readDerived( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 PKey )
	{
		final String S_ProcName = "CFSecRamSecSession.readDerived";
		ICFSecSecSession buff;
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
	public ICFSecSecSession lockDerived( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 PKey )
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

	@Override
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

	@Override
	public ICFSecSecSession[] readDerivedBySecUserIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 SecUserId )
	{
		final String S_ProcName = "CFSecRamSecSession.readDerivedBySecUserIdx";
		CFSecBuffSecSessionBySecUserIdxKey key = (CFSecBuffSecSessionBySecUserIdxKey)schema.getCFSecBuffFactory().getFactorySecSession().newBySecUserIdxKey();

		key.setRequiredSecUserId( SecUserId );
		ICFSecSecSession[] recArray;
		if( dictBySecUserIdx.containsKey( key ) ) {
			Map< ICFLibKeyHash256, CFSecBuffSecSession > subdictSecUserIdx
				= dictBySecUserIdx.get( key );
			recArray = new ICFSecSecSession[ subdictSecUserIdx.size() ];
			Iterator< CFSecBuffSecSession > iter = subdictSecUserIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< ICFLibKeyHash256, CFSecBuffSecSession > subdictSecUserIdx
				= new HashMap< ICFLibKeyHash256, CFSecBuffSecSession >();
			dictBySecUserIdx.put( key, subdictSecUserIdx );
			recArray = new ICFSecSecSession[0];
		}
		return( recArray );
	}

	@Override
	public ICFSecSecSession readDerivedByStartIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 SecUserId,
		LocalDateTime Start )
	{
		final String S_ProcName = "CFSecRamSecSession.readDerivedByStartIdx";
		CFSecBuffSecSessionByStartIdxKey key = (CFSecBuffSecSessionByStartIdxKey)schema.getCFSecBuffFactory().getFactorySecSession().newByStartIdxKey();

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

	@Override
	public ICFSecSecSession[] readDerivedByFinishIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 SecUserId,
		LocalDateTime Finish )
	{
		final String S_ProcName = "CFSecRamSecSession.readDerivedByFinishIdx";
		CFSecBuffSecSessionByFinishIdxKey key = (CFSecBuffSecSessionByFinishIdxKey)schema.getCFSecBuffFactory().getFactorySecSession().newByFinishIdxKey();

		key.setRequiredSecUserId( SecUserId );
		key.setOptionalFinish( Finish );
		ICFSecSecSession[] recArray;
		if( dictByFinishIdx.containsKey( key ) ) {
			Map< ICFLibKeyHash256, CFSecBuffSecSession > subdictFinishIdx
				= dictByFinishIdx.get( key );
			recArray = new ICFSecSecSession[ subdictFinishIdx.size() ];
			Iterator< CFSecBuffSecSession > iter = subdictFinishIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< ICFLibKeyHash256, CFSecBuffSecSession > subdictFinishIdx
				= new HashMap< ICFLibKeyHash256, CFSecBuffSecSession >();
			dictByFinishIdx.put( key, subdictFinishIdx );
			recArray = new ICFSecSecSession[0];
		}
		return( recArray );
	}

	@Override
	public ICFSecSecSession[] readDerivedBySecProxyIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 SecProxyId )
	{
		final String S_ProcName = "CFSecRamSecSession.readDerivedBySecProxyIdx";
		CFSecBuffSecSessionBySecProxyIdxKey key = (CFSecBuffSecSessionBySecProxyIdxKey)schema.getCFSecBuffFactory().getFactorySecSession().newBySecProxyIdxKey();

		key.setOptionalSecProxyId( SecProxyId );
		ICFSecSecSession[] recArray;
		if( dictBySecProxyIdx.containsKey( key ) ) {
			Map< ICFLibKeyHash256, CFSecBuffSecSession > subdictSecProxyIdx
				= dictBySecProxyIdx.get( key );
			recArray = new ICFSecSecSession[ subdictSecProxyIdx.size() ];
			Iterator< CFSecBuffSecSession > iter = subdictSecProxyIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< ICFLibKeyHash256, CFSecBuffSecSession > subdictSecProxyIdx
				= new HashMap< ICFLibKeyHash256, CFSecBuffSecSession >();
			dictBySecProxyIdx.put( key, subdictSecProxyIdx );
			recArray = new ICFSecSecSession[0];
		}
		return( recArray );
	}

	@Override
	public ICFSecSecSession readDerivedByIdIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 SecSessionId )
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

	@Override
	public ICFSecSecSession readRec( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 PKey )
	{
		final String S_ProcName = "CFSecRamSecSession.readRec";
		ICFSecSecSession buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecSecSession.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecSession lockRec( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 PKey )
	{
		final String S_ProcName = "lockRec";
		ICFSecSecSession buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecSecSession.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	@Override
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
	@Override
	public ICFSecSecSession[] pageAllRec( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 priorSecSessionId )
	{
		final String S_ProcName = "pageAllRec";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	@Override
	public ICFSecSecSession readRecByIdIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 SecSessionId )
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

	@Override
	public ICFSecSecSession[] readRecBySecUserIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 SecUserId )
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

	@Override
	public ICFSecSecSession readRecByStartIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 SecUserId,
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

	@Override
	public ICFSecSecSession[] readRecByFinishIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 SecUserId,
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

	@Override
	public ICFSecSecSession[] readRecBySecProxyIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 SecProxyId )
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
	@Override
	public ICFSecSecSession[] pageRecBySecUserIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 SecUserId,
		ICFLibKeyHash256 priorSecSessionId )
	{
		final String S_ProcName = "pageRecBySecUserIdx";
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
	@Override
	public ICFSecSecSession[] pageRecByFinishIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 SecUserId,
		LocalDateTime Finish,
		ICFLibKeyHash256 priorSecSessionId )
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
	@Override
	public ICFSecSecSession[] pageRecBySecProxyIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 SecProxyId,
		ICFLibKeyHash256 priorSecSessionId )
	{
		final String S_ProcName = "pageRecBySecProxyIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	public ICFSecSecSession updateSecSession( ICFSecAuthorization Authorization,
		ICFSecSecSession iBuff )
	{
		CFSecBuffSecSession Buff = (CFSecBuffSecSession)ensureRec(iBuff);
		ICFLibKeyHash256 pkey = (ICFLibKeyHash256)Buff.getPKey();
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
		CFSecBuffSecSessionBySecUserIdxKey existingKeySecUserIdx = (CFSecBuffSecSessionBySecUserIdxKey)schema.getCFSecBuffFactory().getFactorySecSession().newBySecUserIdxKey();
		existingKeySecUserIdx.setRequiredSecUserId( existing.getRequiredSecUserId() );

		CFSecBuffSecSessionBySecUserIdxKey newKeySecUserIdx = (CFSecBuffSecSessionBySecUserIdxKey)schema.getCFSecBuffFactory().getFactorySecSession().newBySecUserIdxKey();
		newKeySecUserIdx.setRequiredSecUserId( Buff.getRequiredSecUserId() );

		CFSecBuffSecSessionByStartIdxKey existingKeyStartIdx = (CFSecBuffSecSessionByStartIdxKey)schema.getCFSecBuffFactory().getFactorySecSession().newByStartIdxKey();
		existingKeyStartIdx.setRequiredSecUserId( existing.getRequiredSecUserId() );
		existingKeyStartIdx.setRequiredStart( existing.getRequiredStart() );

		CFSecBuffSecSessionByStartIdxKey newKeyStartIdx = (CFSecBuffSecSessionByStartIdxKey)schema.getCFSecBuffFactory().getFactorySecSession().newByStartIdxKey();
		newKeyStartIdx.setRequiredSecUserId( Buff.getRequiredSecUserId() );
		newKeyStartIdx.setRequiredStart( Buff.getRequiredStart() );

		CFSecBuffSecSessionByFinishIdxKey existingKeyFinishIdx = (CFSecBuffSecSessionByFinishIdxKey)schema.getCFSecBuffFactory().getFactorySecSession().newByFinishIdxKey();
		existingKeyFinishIdx.setRequiredSecUserId( existing.getRequiredSecUserId() );
		existingKeyFinishIdx.setOptionalFinish( existing.getOptionalFinish() );

		CFSecBuffSecSessionByFinishIdxKey newKeyFinishIdx = (CFSecBuffSecSessionByFinishIdxKey)schema.getCFSecBuffFactory().getFactorySecSession().newByFinishIdxKey();
		newKeyFinishIdx.setRequiredSecUserId( Buff.getRequiredSecUserId() );
		newKeyFinishIdx.setOptionalFinish( Buff.getOptionalFinish() );

		CFSecBuffSecSessionBySecProxyIdxKey existingKeySecProxyIdx = (CFSecBuffSecSessionBySecProxyIdxKey)schema.getCFSecBuffFactory().getFactorySecSession().newBySecProxyIdxKey();
		existingKeySecProxyIdx.setOptionalSecProxyId( existing.getOptionalSecProxyId() );

		CFSecBuffSecSessionBySecProxyIdxKey newKeySecProxyIdx = (CFSecBuffSecSessionBySecProxyIdxKey)schema.getCFSecBuffFactory().getFactorySecSession().newBySecProxyIdxKey();
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

		Map< ICFLibKeyHash256, CFSecBuffSecSession > subdict;

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
			subdict = new HashMap< ICFLibKeyHash256, CFSecBuffSecSession >();
			dictBySecUserIdx.put( newKeySecUserIdx, subdict );
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
			subdict = new HashMap< ICFLibKeyHash256, CFSecBuffSecSession >();
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
			subdict = new HashMap< ICFLibKeyHash256, CFSecBuffSecSession >();
			dictBySecProxyIdx.put( newKeySecProxyIdx, subdict );
		}
		subdict.put( pkey, Buff );

		return(Buff);
	}

	@Override
	public void deleteSecSession( ICFSecAuthorization Authorization,
		ICFSecSecSession iBuff )
	{
		final String S_ProcName = "CFSecRamSecSessionTable.deleteSecSession() ";
		CFSecBuffSecSession Buff = (CFSecBuffSecSession)ensureRec(iBuff);
		int classCode;
		ICFLibKeyHash256 pkey = (ICFLibKeyHash256)(Buff.getPKey());
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
		CFSecBuffSecSessionBySecUserIdxKey keySecUserIdx = (CFSecBuffSecSessionBySecUserIdxKey)schema.getCFSecBuffFactory().getFactorySecSession().newBySecUserIdxKey();
		keySecUserIdx.setRequiredSecUserId( existing.getRequiredSecUserId() );

		CFSecBuffSecSessionByStartIdxKey keyStartIdx = (CFSecBuffSecSessionByStartIdxKey)schema.getCFSecBuffFactory().getFactorySecSession().newByStartIdxKey();
		keyStartIdx.setRequiredSecUserId( existing.getRequiredSecUserId() );
		keyStartIdx.setRequiredStart( existing.getRequiredStart() );

		CFSecBuffSecSessionByFinishIdxKey keyFinishIdx = (CFSecBuffSecSessionByFinishIdxKey)schema.getCFSecBuffFactory().getFactorySecSession().newByFinishIdxKey();
		keyFinishIdx.setRequiredSecUserId( existing.getRequiredSecUserId() );
		keyFinishIdx.setOptionalFinish( existing.getOptionalFinish() );

		CFSecBuffSecSessionBySecProxyIdxKey keySecProxyIdx = (CFSecBuffSecSessionBySecProxyIdxKey)schema.getCFSecBuffFactory().getFactorySecSession().newBySecProxyIdxKey();
		keySecProxyIdx.setOptionalSecProxyId( existing.getOptionalSecProxyId() );

		// Validate reverse foreign keys

		// Delete is valid
		Map< ICFLibKeyHash256, CFSecBuffSecSession > subdict;

		dictByPKey.remove( pkey );

		subdict = dictBySecUserIdx.get( keySecUserIdx );
		subdict.remove( pkey );

		dictByStartIdx.remove( keyStartIdx );

		subdict = dictByFinishIdx.get( keyFinishIdx );
		subdict.remove( pkey );

		subdict = dictBySecProxyIdx.get( keySecProxyIdx );
		subdict.remove( pkey );

	}
	@Override
	public void deleteSecSessionByIdIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 argKey )
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

	@Override
	public void deleteSecSessionBySecUserIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 argSecUserId )
	{
		CFSecBuffSecSessionBySecUserIdxKey key = (CFSecBuffSecSessionBySecUserIdxKey)schema.getCFSecBuffFactory().getFactorySecSession().newBySecUserIdxKey();
		key.setRequiredSecUserId( argSecUserId );
		deleteSecSessionBySecUserIdx( Authorization, key );
	}

	@Override
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

	@Override
	public void deleteSecSessionByStartIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 argSecUserId,
		LocalDateTime argStart )
	{
		CFSecBuffSecSessionByStartIdxKey key = (CFSecBuffSecSessionByStartIdxKey)schema.getCFSecBuffFactory().getFactorySecSession().newByStartIdxKey();
		key.setRequiredSecUserId( argSecUserId );
		key.setRequiredStart( argStart );
		deleteSecSessionByStartIdx( Authorization, key );
	}

	@Override
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

	@Override
	public void deleteSecSessionByFinishIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 argSecUserId,
		LocalDateTime argFinish )
	{
		CFSecBuffSecSessionByFinishIdxKey key = (CFSecBuffSecSessionByFinishIdxKey)schema.getCFSecBuffFactory().getFactorySecSession().newByFinishIdxKey();
		key.setRequiredSecUserId( argSecUserId );
		key.setOptionalFinish( argFinish );
		deleteSecSessionByFinishIdx( Authorization, key );
	}

	@Override
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

	@Override
	public void deleteSecSessionBySecProxyIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 argSecProxyId )
	{
		CFSecBuffSecSessionBySecProxyIdxKey key = (CFSecBuffSecSessionBySecProxyIdxKey)schema.getCFSecBuffFactory().getFactorySecSession().newBySecProxyIdxKey();
		key.setOptionalSecProxyId( argSecProxyId );
		deleteSecSessionBySecProxyIdx( Authorization, key );
	}

	@Override
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
