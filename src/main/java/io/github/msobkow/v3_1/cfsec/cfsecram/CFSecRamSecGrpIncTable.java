
// Description: Java 25 in-memory RAM DbIO implementation for SecGrpInc.

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
 *	CFSecRamSecGrpIncTable in-memory RAM DbIO implementation
 *	for SecGrpInc.
 */
public class CFSecRamSecGrpIncTable
	implements ICFSecSecGrpIncTable
{
	private ICFSecSchema schema;
	private Map< CFLibDbKeyHash256,
				CFSecBuffSecGrpInc > dictByPKey
		= new HashMap< CFLibDbKeyHash256,
				CFSecBuffSecGrpInc >();
	private Map< CFSecBuffSecGrpIncByClusterIdxKey,
				Map< CFLibDbKeyHash256,
					CFSecBuffSecGrpInc >> dictByClusterIdx
		= new HashMap< CFSecBuffSecGrpIncByClusterIdxKey,
				Map< CFLibDbKeyHash256,
					CFSecBuffSecGrpInc >>();
	private Map< CFSecBuffSecGrpIncByGroupIdxKey,
				Map< CFLibDbKeyHash256,
					CFSecBuffSecGrpInc >> dictByGroupIdx
		= new HashMap< CFSecBuffSecGrpIncByGroupIdxKey,
				Map< CFLibDbKeyHash256,
					CFSecBuffSecGrpInc >>();
	private Map< CFSecBuffSecGrpIncByIncludeIdxKey,
				Map< CFLibDbKeyHash256,
					CFSecBuffSecGrpInc >> dictByIncludeIdx
		= new HashMap< CFSecBuffSecGrpIncByIncludeIdxKey,
				Map< CFLibDbKeyHash256,
					CFSecBuffSecGrpInc >>();
	private Map< CFSecBuffSecGrpIncByUIncludeIdxKey,
			CFSecBuffSecGrpInc > dictByUIncludeIdx
		= new HashMap< CFSecBuffSecGrpIncByUIncludeIdxKey,
			CFSecBuffSecGrpInc >();

	public CFSecRamSecGrpIncTable( ICFSecSchema argSchema ) {
		schema = argSchema;
	}

	public CFSecBuffSecGrpInc ensureRec(ICFSecSecGrpInc rec) {
		if (rec == null) {
			return( null );
		}
		else {
			int classCode = rec.getClassCode();
			if (classCode == ICFSecSecGrpInc.CLASS_CODE) {
				return( ((CFSecBuffSecGrpIncDefaultFactory)(schema.getFactorySecGrpInc())).ensureRec(rec) );
			}
			else {
				throw new CFLibUnsupportedClassException(getClass(), "ensureRec", "rec", (Integer)classCode, "Classcode not recognized: " + Integer.toString(classCode));
			}
		}
	}

	public ICFSecSecGrpInc createSecGrpInc( ICFSecAuthorization Authorization,
		ICFSecSecGrpInc iBuff )
	{
		final String S_ProcName = "createSecGrpInc";
		
		CFSecBuffSecGrpInc Buff = ensureRec(iBuff);
		CFLibDbKeyHash256 pkey;
		pkey = schema.nextSecGrpIncIdGen();
		Buff.setRequiredSecGrpIncId( pkey );
		CFSecBuffSecGrpIncByClusterIdxKey keyClusterIdx = (CFSecBuffSecGrpIncByClusterIdxKey)schema.getFactorySecGrpInc().newByClusterIdxKey();
		keyClusterIdx.setRequiredClusterId( Buff.getRequiredClusterId() );

		CFSecBuffSecGrpIncByGroupIdxKey keyGroupIdx = (CFSecBuffSecGrpIncByGroupIdxKey)schema.getFactorySecGrpInc().newByGroupIdxKey();
		keyGroupIdx.setRequiredSecGroupId( Buff.getRequiredSecGroupId() );

		CFSecBuffSecGrpIncByIncludeIdxKey keyIncludeIdx = (CFSecBuffSecGrpIncByIncludeIdxKey)schema.getFactorySecGrpInc().newByIncludeIdxKey();
		keyIncludeIdx.setRequiredIncludeGroupId( Buff.getRequiredIncludeGroupId() );

		CFSecBuffSecGrpIncByUIncludeIdxKey keyUIncludeIdx = (CFSecBuffSecGrpIncByUIncludeIdxKey)schema.getFactorySecGrpInc().newByUIncludeIdxKey();
		keyUIncludeIdx.setRequiredClusterId( Buff.getRequiredClusterId() );
		keyUIncludeIdx.setRequiredSecGroupId( Buff.getRequiredSecGroupId() );
		keyUIncludeIdx.setRequiredIncludeGroupId( Buff.getRequiredIncludeGroupId() );

		// Validate unique indexes

		if( dictByPKey.containsKey( pkey ) ) {
			throw new CFLibPrimaryKeyNotNewException( getClass(), S_ProcName, pkey );
		}

		if( dictByUIncludeIdx.containsKey( keyUIncludeIdx ) ) {
			throw new CFLibUniqueIndexViolationException( getClass(),
				S_ProcName,
				"SecGrpIncUIncludeIdx",
				"SecGrpIncUIncludeIdx",
				keyUIncludeIdx );
		}

		// Validate foreign keys

		{
			boolean allNull = true;
			allNull = false;
			if( ! allNull ) {
				if( null == schema.getTableCluster().readDerivedByIdIdx( Authorization,
						Buff.getRequiredClusterId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						S_ProcName,
						"Owner",
						"Owner",
						"SecGrpIncCluster",
						"SecGrpIncCluster",
						"Cluster",
						"Cluster",
						null );
				}
			}
		}

		{
			boolean allNull = true;
			allNull = false;
			if( ! allNull ) {
				if( null == schema.getTableSecGroup().readDerivedByIdIdx( Authorization,
						Buff.getRequiredSecGroupId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						S_ProcName,
						"Container",
						"Container",
						"SecGrpIncGroup",
						"SecGrpIncGroup",
						"SecGroup",
						"SecGroup",
						null );
				}
			}
		}

		// Proceed with adding the new record

		dictByPKey.put( pkey, Buff );

		Map< CFLibDbKeyHash256, CFSecBuffSecGrpInc > subdictClusterIdx;
		if( dictByClusterIdx.containsKey( keyClusterIdx ) ) {
			subdictClusterIdx = dictByClusterIdx.get( keyClusterIdx );
		}
		else {
			subdictClusterIdx = new HashMap< CFLibDbKeyHash256, CFSecBuffSecGrpInc >();
			dictByClusterIdx.put( keyClusterIdx, subdictClusterIdx );
		}
		subdictClusterIdx.put( pkey, Buff );

		Map< CFLibDbKeyHash256, CFSecBuffSecGrpInc > subdictGroupIdx;
		if( dictByGroupIdx.containsKey( keyGroupIdx ) ) {
			subdictGroupIdx = dictByGroupIdx.get( keyGroupIdx );
		}
		else {
			subdictGroupIdx = new HashMap< CFLibDbKeyHash256, CFSecBuffSecGrpInc >();
			dictByGroupIdx.put( keyGroupIdx, subdictGroupIdx );
		}
		subdictGroupIdx.put( pkey, Buff );

		Map< CFLibDbKeyHash256, CFSecBuffSecGrpInc > subdictIncludeIdx;
		if( dictByIncludeIdx.containsKey( keyIncludeIdx ) ) {
			subdictIncludeIdx = dictByIncludeIdx.get( keyIncludeIdx );
		}
		else {
			subdictIncludeIdx = new HashMap< CFLibDbKeyHash256, CFSecBuffSecGrpInc >();
			dictByIncludeIdx.put( keyIncludeIdx, subdictIncludeIdx );
		}
		subdictIncludeIdx.put( pkey, Buff );

		dictByUIncludeIdx.put( keyUIncludeIdx, Buff );

		if (Buff == null) {
			return( null );
		}
		else {
			int classCode = Buff.getClassCode();
			if (classCode == ICFSecSecGrpInc.CLASS_CODE) {
				CFSecBuffSecGrpInc retbuff = ((CFSecBuffSecGrpInc)(schema.getFactorySecGrpInc().newRec()));
				retbuff.set(Buff);
				return( retbuff );
			}
			else {
				throw new CFLibUnsupportedClassException(getClass(), S_ProcName, "-create-buff-cloning-", (Integer)classCode, "Classcode not recognized: " + Integer.toString(classCode));
			}
		}
	}

	public ICFSecSecGrpInc readDerived( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 PKey )
	{
		final String S_ProcName = "CFSecRamSecGrpInc.readDerived";
		ICFSecSecGrpInc buff;
		if( dictByPKey.containsKey( PKey ) ) {
			buff = dictByPKey.get( PKey );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public ICFSecSecGrpInc lockDerived( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 PKey )
	{
		final String S_ProcName = "CFSecRamSecGrpInc.readDerived";
		ICFSecSecGrpInc buff;
		if( dictByPKey.containsKey( PKey ) ) {
			buff = dictByPKey.get( PKey );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public ICFSecSecGrpInc[] readAllDerived( ICFSecAuthorization Authorization ) {
		final String S_ProcName = "CFSecRamSecGrpInc.readAllDerived";
		ICFSecSecGrpInc[] retList = new ICFSecSecGrpInc[ dictByPKey.values().size() ];
		Iterator< CFSecBuffSecGrpInc > iter = dictByPKey.values().iterator();
		int idx = 0;
		while( iter.hasNext() ) {
			retList[ idx++ ] = iter.next();
		}
		return( retList );
	}

	public ICFSecSecGrpInc[] readDerivedByClusterIdx( ICFSecAuthorization Authorization,
		long ClusterId )
	{
		final String S_ProcName = "CFSecRamSecGrpInc.readDerivedByClusterIdx";
		CFSecBuffSecGrpIncByClusterIdxKey key = (CFSecBuffSecGrpIncByClusterIdxKey)schema.getFactorySecGrpInc().newByClusterIdxKey();
		key.setRequiredClusterId( ClusterId );

		ICFSecSecGrpInc[] recArray;
		if( dictByClusterIdx.containsKey( key ) ) {
			Map< CFLibDbKeyHash256, CFSecBuffSecGrpInc > subdictClusterIdx
				= dictByClusterIdx.get( key );
			recArray = new ICFSecSecGrpInc[ subdictClusterIdx.size() ];
			Iterator< CFSecBuffSecGrpInc > iter = subdictClusterIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFLibDbKeyHash256, CFSecBuffSecGrpInc > subdictClusterIdx
				= new HashMap< CFLibDbKeyHash256, CFSecBuffSecGrpInc >();
			dictByClusterIdx.put( key, subdictClusterIdx );
			recArray = new ICFSecSecGrpInc[0];
		}
		return( recArray );
	}

	public ICFSecSecGrpInc[] readDerivedByGroupIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecGroupId )
	{
		final String S_ProcName = "CFSecRamSecGrpInc.readDerivedByGroupIdx";
		CFSecBuffSecGrpIncByGroupIdxKey key = (CFSecBuffSecGrpIncByGroupIdxKey)schema.getFactorySecGrpInc().newByGroupIdxKey();
		key.setRequiredSecGroupId( SecGroupId );

		ICFSecSecGrpInc[] recArray;
		if( dictByGroupIdx.containsKey( key ) ) {
			Map< CFLibDbKeyHash256, CFSecBuffSecGrpInc > subdictGroupIdx
				= dictByGroupIdx.get( key );
			recArray = new ICFSecSecGrpInc[ subdictGroupIdx.size() ];
			Iterator< CFSecBuffSecGrpInc > iter = subdictGroupIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFLibDbKeyHash256, CFSecBuffSecGrpInc > subdictGroupIdx
				= new HashMap< CFLibDbKeyHash256, CFSecBuffSecGrpInc >();
			dictByGroupIdx.put( key, subdictGroupIdx );
			recArray = new ICFSecSecGrpInc[0];
		}
		return( recArray );
	}

	public ICFSecSecGrpInc[] readDerivedByIncludeIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 IncludeGroupId )
	{
		final String S_ProcName = "CFSecRamSecGrpInc.readDerivedByIncludeIdx";
		CFSecBuffSecGrpIncByIncludeIdxKey key = (CFSecBuffSecGrpIncByIncludeIdxKey)schema.getFactorySecGrpInc().newByIncludeIdxKey();
		key.setRequiredIncludeGroupId( IncludeGroupId );

		ICFSecSecGrpInc[] recArray;
		if( dictByIncludeIdx.containsKey( key ) ) {
			Map< CFLibDbKeyHash256, CFSecBuffSecGrpInc > subdictIncludeIdx
				= dictByIncludeIdx.get( key );
			recArray = new ICFSecSecGrpInc[ subdictIncludeIdx.size() ];
			Iterator< CFSecBuffSecGrpInc > iter = subdictIncludeIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFLibDbKeyHash256, CFSecBuffSecGrpInc > subdictIncludeIdx
				= new HashMap< CFLibDbKeyHash256, CFSecBuffSecGrpInc >();
			dictByIncludeIdx.put( key, subdictIncludeIdx );
			recArray = new ICFSecSecGrpInc[0];
		}
		return( recArray );
	}

	public ICFSecSecGrpInc readDerivedByUIncludeIdx( ICFSecAuthorization Authorization,
		long ClusterId,
		CFLibDbKeyHash256 SecGroupId,
		CFLibDbKeyHash256 IncludeGroupId )
	{
		final String S_ProcName = "CFSecRamSecGrpInc.readDerivedByUIncludeIdx";
		CFSecBuffSecGrpIncByUIncludeIdxKey key = (CFSecBuffSecGrpIncByUIncludeIdxKey)schema.getFactorySecGrpInc().newByUIncludeIdxKey();
		key.setRequiredClusterId( ClusterId );
		key.setRequiredSecGroupId( SecGroupId );
		key.setRequiredIncludeGroupId( IncludeGroupId );

		ICFSecSecGrpInc buff;
		if( dictByUIncludeIdx.containsKey( key ) ) {
			buff = dictByUIncludeIdx.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public ICFSecSecGrpInc readDerivedByIdIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecGrpIncId )
	{
		final String S_ProcName = "CFSecRamSecGrpInc.readDerivedByIdIdx() ";
		ICFSecSecGrpInc buff;
		if( dictByPKey.containsKey( SecGrpIncId ) ) {
			buff = dictByPKey.get( SecGrpIncId );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public ICFSecSecGrpInc readRec( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 PKey )
	{
		final String S_ProcName = "CFSecRamSecGrpInc.readRec";
		ICFSecSecGrpInc buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecSecGrpInc.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	public ICFSecSecGrpInc lockRec( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 PKey )
	{
		final String S_ProcName = "lockRec";
		ICFSecSecGrpInc buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecSecGrpInc.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	public ICFSecSecGrpInc[] readAllRec( ICFSecAuthorization Authorization )
	{
		final String S_ProcName = "CFSecRamSecGrpInc.readAllRec";
		ICFSecSecGrpInc buff;
		ArrayList<ICFSecSecGrpInc> filteredList = new ArrayList<ICFSecSecGrpInc>();
		ICFSecSecGrpInc[] buffList = readAllDerived( Authorization );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecGrpInc.CLASS_CODE ) ) {
				filteredList.add( buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecGrpInc[0] ) );
	}

	/**
	 *	Read a page of all the specific SecGrpInc buffer instances.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@return All the specific SecGrpInc instances in the database accessible for the Authorization.
	 */
	public ICFSecSecGrpInc[] pageAllRec( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 priorSecGrpIncId )
	{
		final String S_ProcName = "pageAllRec";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	public ICFSecSecGrpInc readRecByIdIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecGrpIncId )
	{
		final String S_ProcName = "CFSecRamSecGrpInc.readRecByIdIdx() ";
		ICFSecSecGrpInc buff = readDerivedByIdIdx( Authorization,
			SecGrpIncId );
		if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecGrpInc.CLASS_CODE ) ) {
			return( (ICFSecSecGrpInc)buff );
		}
		else {
			return( null );
		}
	}

	public ICFSecSecGrpInc[] readRecByClusterIdx( ICFSecAuthorization Authorization,
		long ClusterId )
	{
		final String S_ProcName = "CFSecRamSecGrpInc.readRecByClusterIdx() ";
		ICFSecSecGrpInc buff;
		ArrayList<ICFSecSecGrpInc> filteredList = new ArrayList<ICFSecSecGrpInc>();
		ICFSecSecGrpInc[] buffList = readDerivedByClusterIdx( Authorization,
			ClusterId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecGrpInc.CLASS_CODE ) ) {
				filteredList.add( (ICFSecSecGrpInc)buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecGrpInc[0] ) );
	}

	public ICFSecSecGrpInc[] readRecByGroupIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecGroupId )
	{
		final String S_ProcName = "CFSecRamSecGrpInc.readRecByGroupIdx() ";
		ICFSecSecGrpInc buff;
		ArrayList<ICFSecSecGrpInc> filteredList = new ArrayList<ICFSecSecGrpInc>();
		ICFSecSecGrpInc[] buffList = readDerivedByGroupIdx( Authorization,
			SecGroupId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecGrpInc.CLASS_CODE ) ) {
				filteredList.add( (ICFSecSecGrpInc)buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecGrpInc[0] ) );
	}

	public ICFSecSecGrpInc[] readRecByIncludeIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 IncludeGroupId )
	{
		final String S_ProcName = "CFSecRamSecGrpInc.readRecByIncludeIdx() ";
		ICFSecSecGrpInc buff;
		ArrayList<ICFSecSecGrpInc> filteredList = new ArrayList<ICFSecSecGrpInc>();
		ICFSecSecGrpInc[] buffList = readDerivedByIncludeIdx( Authorization,
			IncludeGroupId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecGrpInc.CLASS_CODE ) ) {
				filteredList.add( (ICFSecSecGrpInc)buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecGrpInc[0] ) );
	}

	public ICFSecSecGrpInc readRecByUIncludeIdx( ICFSecAuthorization Authorization,
		long ClusterId,
		CFLibDbKeyHash256 SecGroupId,
		CFLibDbKeyHash256 IncludeGroupId )
	{
		final String S_ProcName = "CFSecRamSecGrpInc.readRecByUIncludeIdx() ";
		ICFSecSecGrpInc buff = readDerivedByUIncludeIdx( Authorization,
			ClusterId,
			SecGroupId,
			IncludeGroupId );
		if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecGrpInc.CLASS_CODE ) ) {
			return( (ICFSecSecGrpInc)buff );
		}
		else {
			return( null );
		}
	}

	/**
	 *	Read a page array of the specific SecGrpInc buffer instances identified by the duplicate key ClusterIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	ClusterId	The SecGrpInc key attribute of the instance generating the id.
	 *
	 *	@return An array of derived buffer instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	public ICFSecSecGrpInc[] pageRecByClusterIdx( ICFSecAuthorization Authorization,
		long ClusterId,
		CFLibDbKeyHash256 priorSecGrpIncId )
	{
		final String S_ProcName = "pageRecByClusterIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	/**
	 *	Read a page array of the specific SecGrpInc buffer instances identified by the duplicate key GroupIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	SecGroupId	The SecGrpInc key attribute of the instance generating the id.
	 *
	 *	@return An array of derived buffer instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	public ICFSecSecGrpInc[] pageRecByGroupIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecGroupId,
		CFLibDbKeyHash256 priorSecGrpIncId )
	{
		final String S_ProcName = "pageRecByGroupIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	/**
	 *	Read a page array of the specific SecGrpInc buffer instances identified by the duplicate key IncludeIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	IncludeGroupId	The SecGrpInc key attribute of the instance generating the id.
	 *
	 *	@return An array of derived buffer instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	public ICFSecSecGrpInc[] pageRecByIncludeIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 IncludeGroupId,
		CFLibDbKeyHash256 priorSecGrpIncId )
	{
		final String S_ProcName = "pageRecByIncludeIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	public ICFSecSecGrpInc updateSecGrpInc( ICFSecAuthorization Authorization,
		ICFSecSecGrpInc iBuff )
	{
		CFSecBuffSecGrpInc Buff = ensureRec(iBuff);
		CFLibDbKeyHash256 pkey = Buff.getPKey();
		CFSecBuffSecGrpInc existing = dictByPKey.get( pkey );
		if( existing == null ) {
			throw new CFLibStaleCacheDetectedException( getClass(),
				"updateSecGrpInc",
				"Existing record not found",
				"Existing record not found",
				"SecGrpInc",
				"SecGrpInc",
				pkey );
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() ) {
			throw new CFLibCollisionDetectedException( getClass(),
				"updateSecGrpInc",
				pkey );
		}
		Buff.setRequiredRevision( Buff.getRequiredRevision() + 1 );
		CFSecBuffSecGrpIncByClusterIdxKey existingKeyClusterIdx = (CFSecBuffSecGrpIncByClusterIdxKey)schema.getFactorySecGrpInc().newByClusterIdxKey();
		existingKeyClusterIdx.setRequiredClusterId( existing.getRequiredClusterId() );

		CFSecBuffSecGrpIncByClusterIdxKey newKeyClusterIdx = (CFSecBuffSecGrpIncByClusterIdxKey)schema.getFactorySecGrpInc().newByClusterIdxKey();
		newKeyClusterIdx.setRequiredClusterId( Buff.getRequiredClusterId() );

		CFSecBuffSecGrpIncByGroupIdxKey existingKeyGroupIdx = (CFSecBuffSecGrpIncByGroupIdxKey)schema.getFactorySecGrpInc().newByGroupIdxKey();
		existingKeyGroupIdx.setRequiredSecGroupId( existing.getRequiredSecGroupId() );

		CFSecBuffSecGrpIncByGroupIdxKey newKeyGroupIdx = (CFSecBuffSecGrpIncByGroupIdxKey)schema.getFactorySecGrpInc().newByGroupIdxKey();
		newKeyGroupIdx.setRequiredSecGroupId( Buff.getRequiredSecGroupId() );

		CFSecBuffSecGrpIncByIncludeIdxKey existingKeyIncludeIdx = (CFSecBuffSecGrpIncByIncludeIdxKey)schema.getFactorySecGrpInc().newByIncludeIdxKey();
		existingKeyIncludeIdx.setRequiredIncludeGroupId( existing.getRequiredIncludeGroupId() );

		CFSecBuffSecGrpIncByIncludeIdxKey newKeyIncludeIdx = (CFSecBuffSecGrpIncByIncludeIdxKey)schema.getFactorySecGrpInc().newByIncludeIdxKey();
		newKeyIncludeIdx.setRequiredIncludeGroupId( Buff.getRequiredIncludeGroupId() );

		CFSecBuffSecGrpIncByUIncludeIdxKey existingKeyUIncludeIdx = (CFSecBuffSecGrpIncByUIncludeIdxKey)schema.getFactorySecGrpInc().newByUIncludeIdxKey();
		existingKeyUIncludeIdx.setRequiredClusterId( existing.getRequiredClusterId() );
		existingKeyUIncludeIdx.setRequiredSecGroupId( existing.getRequiredSecGroupId() );
		existingKeyUIncludeIdx.setRequiredIncludeGroupId( existing.getRequiredIncludeGroupId() );

		CFSecBuffSecGrpIncByUIncludeIdxKey newKeyUIncludeIdx = (CFSecBuffSecGrpIncByUIncludeIdxKey)schema.getFactorySecGrpInc().newByUIncludeIdxKey();
		newKeyUIncludeIdx.setRequiredClusterId( Buff.getRequiredClusterId() );
		newKeyUIncludeIdx.setRequiredSecGroupId( Buff.getRequiredSecGroupId() );
		newKeyUIncludeIdx.setRequiredIncludeGroupId( Buff.getRequiredIncludeGroupId() );

		// Check unique indexes

		if( ! existingKeyUIncludeIdx.equals( newKeyUIncludeIdx ) ) {
			if( dictByUIncludeIdx.containsKey( newKeyUIncludeIdx ) ) {
				throw new CFLibUniqueIndexViolationException( getClass(),
					"updateSecGrpInc",
					"SecGrpIncUIncludeIdx",
					"SecGrpIncUIncludeIdx",
					newKeyUIncludeIdx );
			}
		}

		// Validate foreign keys

		{
			boolean allNull = true;

			if( allNull ) {
				if( null == schema.getTableCluster().readDerivedByIdIdx( Authorization,
						Buff.getRequiredClusterId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						"updateSecGrpInc",
						"Owner",
						"Owner",
						"SecGrpIncCluster",
						"SecGrpIncCluster",
						"Cluster",
						"Cluster",
						null );
				}
			}
		}

		{
			boolean allNull = true;

			if( allNull ) {
				if( null == schema.getTableSecGroup().readDerivedByIdIdx( Authorization,
						Buff.getRequiredSecGroupId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						"updateSecGrpInc",
						"Container",
						"Container",
						"SecGrpIncGroup",
						"SecGrpIncGroup",
						"SecGroup",
						"SecGroup",
						null );
				}
			}
		}

		// Update is valid

		Map< CFLibDbKeyHash256, CFSecBuffSecGrpInc > subdict;

		dictByPKey.remove( pkey );
		dictByPKey.put( pkey, Buff );

		subdict = dictByClusterIdx.get( existingKeyClusterIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictByClusterIdx.containsKey( newKeyClusterIdx ) ) {
			subdict = dictByClusterIdx.get( newKeyClusterIdx );
		}
		else {
			subdict = new HashMap< CFLibDbKeyHash256, CFSecBuffSecGrpInc >();
			dictByClusterIdx.put( newKeyClusterIdx, subdict );
		}
		subdict.put( pkey, Buff );

		subdict = dictByGroupIdx.get( existingKeyGroupIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictByGroupIdx.containsKey( newKeyGroupIdx ) ) {
			subdict = dictByGroupIdx.get( newKeyGroupIdx );
		}
		else {
			subdict = new HashMap< CFLibDbKeyHash256, CFSecBuffSecGrpInc >();
			dictByGroupIdx.put( newKeyGroupIdx, subdict );
		}
		subdict.put( pkey, Buff );

		subdict = dictByIncludeIdx.get( existingKeyIncludeIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictByIncludeIdx.containsKey( newKeyIncludeIdx ) ) {
			subdict = dictByIncludeIdx.get( newKeyIncludeIdx );
		}
		else {
			subdict = new HashMap< CFLibDbKeyHash256, CFSecBuffSecGrpInc >();
			dictByIncludeIdx.put( newKeyIncludeIdx, subdict );
		}
		subdict.put( pkey, Buff );

		dictByUIncludeIdx.remove( existingKeyUIncludeIdx );
		dictByUIncludeIdx.put( newKeyUIncludeIdx, Buff );

		return(Buff);
	}

	public void deleteSecGrpInc( ICFSecAuthorization Authorization,
		ICFSecSecGrpInc iBuff )
	{
		final String S_ProcName = "CFSecRamSecGrpIncTable.deleteSecGrpInc() ";
		CFSecBuffSecGrpInc Buff = ensureRec(iBuff);
		int classCode;
		CFLibDbKeyHash256 pkey = (CFLibDbKeyHash256)(Buff.getPKey());
		CFSecBuffSecGrpInc existing = dictByPKey.get( pkey );
		if( existing == null ) {
			return;
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() )
		{
			throw new CFLibCollisionDetectedException( getClass(),
				"deleteSecGrpInc",
				pkey );
		}
		CFSecBuffSecGrpIncByClusterIdxKey keyClusterIdx = (CFSecBuffSecGrpIncByClusterIdxKey)schema.getFactorySecGrpInc().newByClusterIdxKey();
		keyClusterIdx.setRequiredClusterId( existing.getRequiredClusterId() );

		CFSecBuffSecGrpIncByGroupIdxKey keyGroupIdx = (CFSecBuffSecGrpIncByGroupIdxKey)schema.getFactorySecGrpInc().newByGroupIdxKey();
		keyGroupIdx.setRequiredSecGroupId( existing.getRequiredSecGroupId() );

		CFSecBuffSecGrpIncByIncludeIdxKey keyIncludeIdx = (CFSecBuffSecGrpIncByIncludeIdxKey)schema.getFactorySecGrpInc().newByIncludeIdxKey();
		keyIncludeIdx.setRequiredIncludeGroupId( existing.getRequiredIncludeGroupId() );

		CFSecBuffSecGrpIncByUIncludeIdxKey keyUIncludeIdx = (CFSecBuffSecGrpIncByUIncludeIdxKey)schema.getFactorySecGrpInc().newByUIncludeIdxKey();
		keyUIncludeIdx.setRequiredClusterId( existing.getRequiredClusterId() );
		keyUIncludeIdx.setRequiredSecGroupId( existing.getRequiredSecGroupId() );
		keyUIncludeIdx.setRequiredIncludeGroupId( existing.getRequiredIncludeGroupId() );

		// Validate reverse foreign keys

		// Delete is valid
		Map< CFLibDbKeyHash256, CFSecBuffSecGrpInc > subdict;

		dictByPKey.remove( pkey );

		subdict = dictByClusterIdx.get( keyClusterIdx );
		subdict.remove( pkey );

		subdict = dictByGroupIdx.get( keyGroupIdx );
		subdict.remove( pkey );

		subdict = dictByIncludeIdx.get( keyIncludeIdx );
		subdict.remove( pkey );

		dictByUIncludeIdx.remove( keyUIncludeIdx );

	}
	public void deleteSecGrpIncByIdIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argKey )
	{
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		CFSecBuffSecGrpInc cur;
		LinkedList<CFSecBuffSecGrpInc> matchSet = new LinkedList<CFSecBuffSecGrpInc>();
		Iterator<CFSecBuffSecGrpInc> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecGrpInc> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecGrpInc)(schema.getTableSecGrpInc().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecGrpIncId() ));
			deleteSecGrpInc( Authorization, cur );
		}
	}

	public void deleteSecGrpIncByClusterIdx( ICFSecAuthorization Authorization,
		long argClusterId )
	{
		CFSecBuffSecGrpIncByClusterIdxKey key = (CFSecBuffSecGrpIncByClusterIdxKey)schema.getFactorySecGrpInc().newByClusterIdxKey();
		key.setRequiredClusterId( argClusterId );
		deleteSecGrpIncByClusterIdx( Authorization, key );
	}

	public void deleteSecGrpIncByClusterIdx( ICFSecAuthorization Authorization,
		ICFSecSecGrpIncByClusterIdxKey argKey )
	{
		CFSecBuffSecGrpInc cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffSecGrpInc> matchSet = new LinkedList<CFSecBuffSecGrpInc>();
		Iterator<CFSecBuffSecGrpInc> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecGrpInc> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecGrpInc)(schema.getTableSecGrpInc().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecGrpIncId() ));
			deleteSecGrpInc( Authorization, cur );
		}
	}

	public void deleteSecGrpIncByGroupIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argSecGroupId )
	{
		CFSecBuffSecGrpIncByGroupIdxKey key = (CFSecBuffSecGrpIncByGroupIdxKey)schema.getFactorySecGrpInc().newByGroupIdxKey();
		key.setRequiredSecGroupId( argSecGroupId );
		deleteSecGrpIncByGroupIdx( Authorization, key );
	}

	public void deleteSecGrpIncByGroupIdx( ICFSecAuthorization Authorization,
		ICFSecSecGrpIncByGroupIdxKey argKey )
	{
		CFSecBuffSecGrpInc cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffSecGrpInc> matchSet = new LinkedList<CFSecBuffSecGrpInc>();
		Iterator<CFSecBuffSecGrpInc> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecGrpInc> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecGrpInc)(schema.getTableSecGrpInc().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecGrpIncId() ));
			deleteSecGrpInc( Authorization, cur );
		}
	}

	public void deleteSecGrpIncByIncludeIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argIncludeGroupId )
	{
		CFSecBuffSecGrpIncByIncludeIdxKey key = (CFSecBuffSecGrpIncByIncludeIdxKey)schema.getFactorySecGrpInc().newByIncludeIdxKey();
		key.setRequiredIncludeGroupId( argIncludeGroupId );
		deleteSecGrpIncByIncludeIdx( Authorization, key );
	}

	public void deleteSecGrpIncByIncludeIdx( ICFSecAuthorization Authorization,
		ICFSecSecGrpIncByIncludeIdxKey argKey )
	{
		CFSecBuffSecGrpInc cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffSecGrpInc> matchSet = new LinkedList<CFSecBuffSecGrpInc>();
		Iterator<CFSecBuffSecGrpInc> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecGrpInc> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecGrpInc)(schema.getTableSecGrpInc().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecGrpIncId() ));
			deleteSecGrpInc( Authorization, cur );
		}
	}

	public void deleteSecGrpIncByUIncludeIdx( ICFSecAuthorization Authorization,
		long argClusterId,
		CFLibDbKeyHash256 argSecGroupId,
		CFLibDbKeyHash256 argIncludeGroupId )
	{
		CFSecBuffSecGrpIncByUIncludeIdxKey key = (CFSecBuffSecGrpIncByUIncludeIdxKey)schema.getFactorySecGrpInc().newByUIncludeIdxKey();
		key.setRequiredClusterId( argClusterId );
		key.setRequiredSecGroupId( argSecGroupId );
		key.setRequiredIncludeGroupId( argIncludeGroupId );
		deleteSecGrpIncByUIncludeIdx( Authorization, key );
	}

	public void deleteSecGrpIncByUIncludeIdx( ICFSecAuthorization Authorization,
		ICFSecSecGrpIncByUIncludeIdxKey argKey )
	{
		CFSecBuffSecGrpInc cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffSecGrpInc> matchSet = new LinkedList<CFSecBuffSecGrpInc>();
		Iterator<CFSecBuffSecGrpInc> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecGrpInc> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecGrpInc)(schema.getTableSecGrpInc().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecGrpIncId() ));
			deleteSecGrpInc( Authorization, cur );
		}
	}
}
