
// Description: Java 25 in-memory RAM DbIO implementation for SecGrpMemb.

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
 *	CFSecRamSecGrpMembTable in-memory RAM DbIO implementation
 *	for SecGrpMemb.
 */
public class CFSecRamSecGrpMembTable
	implements ICFSecSecGrpMembTable
{
	private ICFSecSchema schema;
	private Map< CFSecSecGrpMembPKey,
				CFSecSecGrpMembBuff > dictByPKey
		= new HashMap< CFSecSecGrpMembPKey,
				CFSecSecGrpMembBuff >();
	private Map< CFSecSecGrpMembByClusterIdxKey,
				Map< CFSecSecGrpMembPKey,
					CFSecSecGrpMembBuff >> dictByClusterIdx
		= new HashMap< CFSecSecGrpMembByClusterIdxKey,
				Map< CFSecSecGrpMembPKey,
					CFSecSecGrpMembBuff >>();
	private Map< CFSecSecGrpMembByGroupIdxKey,
				Map< CFSecSecGrpMembPKey,
					CFSecSecGrpMembBuff >> dictByGroupIdx
		= new HashMap< CFSecSecGrpMembByGroupIdxKey,
				Map< CFSecSecGrpMembPKey,
					CFSecSecGrpMembBuff >>();
	private Map< CFSecSecGrpMembByUserIdxKey,
				Map< CFSecSecGrpMembPKey,
					CFSecSecGrpMembBuff >> dictByUserIdx
		= new HashMap< CFSecSecGrpMembByUserIdxKey,
				Map< CFSecSecGrpMembPKey,
					CFSecSecGrpMembBuff >>();
	private Map< CFSecSecGrpMembByUUserIdxKey,
			CFSecSecGrpMembBuff > dictByUUserIdx
		= new HashMap< CFSecSecGrpMembByUUserIdxKey,
			CFSecSecGrpMembBuff >();

	public CFSecRamSecGrpMembTable( ICFSecSchema argSchema ) {
		schema = argSchema;
	}

	public void createSecGrpMemb( CFSecAuthorization Authorization,
		CFSecSecGrpMembBuff Buff )
	{
		final String S_ProcName = "createSecGrpMemb";
		CFSecSecGrpMembPKey pkey = schema.getFactorySecGrpMemb().newPKey();
		pkey.setRequiredSecGrpMembId( schema.nextSecGrpMembIdGen() );
		Buff.setRequiredSecGrpMembId( pkey.getRequiredSecGrpMembId() );
		CFSecSecGrpMembByClusterIdxKey keyClusterIdx = schema.getFactorySecGrpMemb().newClusterIdxKey();
		keyClusterIdx.setRequiredClusterId( Buff.getRequiredClusterId() );

		CFSecSecGrpMembByGroupIdxKey keyGroupIdx = schema.getFactorySecGrpMemb().newGroupIdxKey();
		keyGroupIdx.setRequiredSecGroupId( Buff.getRequiredSecGroupId() );

		CFSecSecGrpMembByUserIdxKey keyUserIdx = schema.getFactorySecGrpMemb().newUserIdxKey();
		keyUserIdx.setRequiredSecUserId( Buff.getRequiredSecUserId() );

		CFSecSecGrpMembByUUserIdxKey keyUUserIdx = schema.getFactorySecGrpMemb().newUUserIdxKey();
		keyUUserIdx.setRequiredClusterId( Buff.getRequiredClusterId() );
		keyUUserIdx.setRequiredSecGroupId( Buff.getRequiredSecGroupId() );
		keyUUserIdx.setRequiredSecUserId( Buff.getRequiredSecUserId() );

		// Validate unique indexes

		if( dictByPKey.containsKey( pkey ) ) {
			throw new CFLibPrimaryKeyNotNewException( getClass(), S_ProcName, pkey );
		}

		if( dictByUUserIdx.containsKey( keyUUserIdx ) ) {
			throw new CFLibUniqueIndexViolationException( getClass(),
				S_ProcName,
				"SecGrpMembUUserIdx",
				keyUUserIdx );
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
						"SecGrpMembCluster",
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
						"SecGrpMembGroup",
						"SecGroup",
						null );
				}
			}
		}

		// Proceed with adding the new record

		dictByPKey.put( pkey, Buff );

		Map< CFSecSecGrpMembPKey, CFSecSecGrpMembBuff > subdictClusterIdx;
		if( dictByClusterIdx.containsKey( keyClusterIdx ) ) {
			subdictClusterIdx = dictByClusterIdx.get( keyClusterIdx );
		}
		else {
			subdictClusterIdx = new HashMap< CFSecSecGrpMembPKey, CFSecSecGrpMembBuff >();
			dictByClusterIdx.put( keyClusterIdx, subdictClusterIdx );
		}
		subdictClusterIdx.put( pkey, Buff );

		Map< CFSecSecGrpMembPKey, CFSecSecGrpMembBuff > subdictGroupIdx;
		if( dictByGroupIdx.containsKey( keyGroupIdx ) ) {
			subdictGroupIdx = dictByGroupIdx.get( keyGroupIdx );
		}
		else {
			subdictGroupIdx = new HashMap< CFSecSecGrpMembPKey, CFSecSecGrpMembBuff >();
			dictByGroupIdx.put( keyGroupIdx, subdictGroupIdx );
		}
		subdictGroupIdx.put( pkey, Buff );

		Map< CFSecSecGrpMembPKey, CFSecSecGrpMembBuff > subdictUserIdx;
		if( dictByUserIdx.containsKey( keyUserIdx ) ) {
			subdictUserIdx = dictByUserIdx.get( keyUserIdx );
		}
		else {
			subdictUserIdx = new HashMap< CFSecSecGrpMembPKey, CFSecSecGrpMembBuff >();
			dictByUserIdx.put( keyUserIdx, subdictUserIdx );
		}
		subdictUserIdx.put( pkey, Buff );

		dictByUUserIdx.put( keyUUserIdx, Buff );

	}

	public CFSecSecGrpMembBuff readDerived( CFSecAuthorization Authorization,
		CFSecSecGrpMembPKey PKey )
	{
		final String S_ProcName = "CFSecRamSecGrpMemb.readDerived";
		CFSecSecGrpMembPKey key = schema.getFactorySecGrpMemb().newPKey();
		key.setRequiredSecGrpMembId( PKey.getRequiredSecGrpMembId() );
		CFSecSecGrpMembBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecSecGrpMembBuff lockDerived( CFSecAuthorization Authorization,
		CFSecSecGrpMembPKey PKey )
	{
		final String S_ProcName = "CFSecRamSecGrpMemb.readDerived";
		CFSecSecGrpMembPKey key = schema.getFactorySecGrpMemb().newPKey();
		key.setRequiredSecGrpMembId( PKey.getRequiredSecGrpMembId() );
		CFSecSecGrpMembBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecSecGrpMembBuff[] readAllDerived( CFSecAuthorization Authorization ) {
		final String S_ProcName = "CFSecRamSecGrpMemb.readAllDerived";
		CFSecSecGrpMembBuff[] retList = new CFSecSecGrpMembBuff[ dictByPKey.values().size() ];
		Iterator< CFSecSecGrpMembBuff > iter = dictByPKey.values().iterator();
		int idx = 0;
		while( iter.hasNext() ) {
			retList[ idx++ ] = iter.next();
		}
		return( retList );
	}

	public CFSecSecGrpMembBuff[] readDerivedByClusterIdx( CFSecAuthorization Authorization,
		long ClusterId )
	{
		final String S_ProcName = "CFSecRamSecGrpMemb.readDerivedByClusterIdx";
		CFSecSecGrpMembByClusterIdxKey key = schema.getFactorySecGrpMemb().newClusterIdxKey();
		key.setRequiredClusterId( ClusterId );

		CFSecSecGrpMembBuff[] recArray;
		if( dictByClusterIdx.containsKey( key ) ) {
			Map< CFSecSecGrpMembPKey, CFSecSecGrpMembBuff > subdictClusterIdx
				= dictByClusterIdx.get( key );
			recArray = new CFSecSecGrpMembBuff[ subdictClusterIdx.size() ];
			Iterator< CFSecSecGrpMembBuff > iter = subdictClusterIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFSecSecGrpMembPKey, CFSecSecGrpMembBuff > subdictClusterIdx
				= new HashMap< CFSecSecGrpMembPKey, CFSecSecGrpMembBuff >();
			dictByClusterIdx.put( key, subdictClusterIdx );
			recArray = new CFSecSecGrpMembBuff[0];
		}
		return( recArray );
	}

	public CFSecSecGrpMembBuff[] readDerivedByGroupIdx( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecGroupId )
	{
		final String S_ProcName = "CFSecRamSecGrpMemb.readDerivedByGroupIdx";
		CFSecSecGrpMembByGroupIdxKey key = schema.getFactorySecGrpMemb().newGroupIdxKey();
		key.setRequiredSecGroupId( SecGroupId );

		CFSecSecGrpMembBuff[] recArray;
		if( dictByGroupIdx.containsKey( key ) ) {
			Map< CFSecSecGrpMembPKey, CFSecSecGrpMembBuff > subdictGroupIdx
				= dictByGroupIdx.get( key );
			recArray = new CFSecSecGrpMembBuff[ subdictGroupIdx.size() ];
			Iterator< CFSecSecGrpMembBuff > iter = subdictGroupIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFSecSecGrpMembPKey, CFSecSecGrpMembBuff > subdictGroupIdx
				= new HashMap< CFSecSecGrpMembPKey, CFSecSecGrpMembBuff >();
			dictByGroupIdx.put( key, subdictGroupIdx );
			recArray = new CFSecSecGrpMembBuff[0];
		}
		return( recArray );
	}

	public CFSecSecGrpMembBuff[] readDerivedByUserIdx( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecUserId )
	{
		final String S_ProcName = "CFSecRamSecGrpMemb.readDerivedByUserIdx";
		CFSecSecGrpMembByUserIdxKey key = schema.getFactorySecGrpMemb().newUserIdxKey();
		key.setRequiredSecUserId( SecUserId );

		CFSecSecGrpMembBuff[] recArray;
		if( dictByUserIdx.containsKey( key ) ) {
			Map< CFSecSecGrpMembPKey, CFSecSecGrpMembBuff > subdictUserIdx
				= dictByUserIdx.get( key );
			recArray = new CFSecSecGrpMembBuff[ subdictUserIdx.size() ];
			Iterator< CFSecSecGrpMembBuff > iter = subdictUserIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFSecSecGrpMembPKey, CFSecSecGrpMembBuff > subdictUserIdx
				= new HashMap< CFSecSecGrpMembPKey, CFSecSecGrpMembBuff >();
			dictByUserIdx.put( key, subdictUserIdx );
			recArray = new CFSecSecGrpMembBuff[0];
		}
		return( recArray );
	}

	public CFSecSecGrpMembBuff readDerivedByUUserIdx( CFSecAuthorization Authorization,
		long ClusterId,
		CFLibDbKeyHash256 SecGroupId,
		CFLibDbKeyHash256 SecUserId )
	{
		final String S_ProcName = "CFSecRamSecGrpMemb.readDerivedByUUserIdx";
		CFSecSecGrpMembByUUserIdxKey key = schema.getFactorySecGrpMemb().newUUserIdxKey();
		key.setRequiredClusterId( ClusterId );
		key.setRequiredSecGroupId( SecGroupId );
		key.setRequiredSecUserId( SecUserId );

		CFSecSecGrpMembBuff buff;
		if( dictByUUserIdx.containsKey( key ) ) {
			buff = dictByUUserIdx.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecSecGrpMembBuff readDerivedByIdIdx( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecGrpMembId )
	{
		final String S_ProcName = "CFSecRamSecGrpMemb.readDerivedByIdIdx() ";
		CFSecSecGrpMembPKey key = schema.getFactorySecGrpMemb().newPKey();
		key.setRequiredSecGrpMembId( SecGrpMembId );

		CFSecSecGrpMembBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecSecGrpMembBuff readBuff( CFSecAuthorization Authorization,
		CFSecSecGrpMembPKey PKey )
	{
		final String S_ProcName = "CFSecRamSecGrpMemb.readBuff";
		CFSecSecGrpMembBuff buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( ! buff.getClassCode().equals( "a00f" ) ) ) {
			buff = null;
		}
		return( buff );
	}

	public CFSecSecGrpMembBuff lockBuff( CFSecAuthorization Authorization,
		CFSecSecGrpMembPKey PKey )
	{
		final String S_ProcName = "lockBuff";
		CFSecSecGrpMembBuff buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( ! buff.getClassCode().equals( "a00f" ) ) ) {
			buff = null;
		}
		return( buff );
	}

	public CFSecSecGrpMembBuff[] readAllBuff( CFSecAuthorization Authorization )
	{
		final String S_ProcName = "CFSecRamSecGrpMemb.readAllBuff";
		CFSecSecGrpMembBuff buff;
		ArrayList<CFSecSecGrpMembBuff> filteredList = new ArrayList<CFSecSecGrpMembBuff>();
		CFSecSecGrpMembBuff[] buffList = readAllDerived( Authorization );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a00f" ) ) {
				filteredList.add( buff );
			}
		}
		return( filteredList.toArray( new CFSecSecGrpMembBuff[0] ) );
	}

	/**
	 *	Read a page of all the specific SecGrpMemb buffer instances.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@return All the specific SecGrpMemb instances in the database accessible for the Authorization.
	 */
	public CFSecSecGrpMembBuff[] pageAllBuff( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 priorSecGrpMembId )
	{
		final String S_ProcName = "pageAllBuff";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	public CFSecSecGrpMembBuff readBuffByIdIdx( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecGrpMembId )
	{
		final String S_ProcName = "CFSecRamSecGrpMemb.readBuffByIdIdx() ";
		CFSecSecGrpMembBuff buff = readDerivedByIdIdx( Authorization,
			SecGrpMembId );
		if( ( buff != null ) && buff.getClassCode().equals( "a00f" ) ) {
			return( (CFSecSecGrpMembBuff)buff );
		}
		else {
			return( null );
		}
	}

	public CFSecSecGrpMembBuff[] readBuffByClusterIdx( CFSecAuthorization Authorization,
		long ClusterId )
	{
		final String S_ProcName = "CFSecRamSecGrpMemb.readBuffByClusterIdx() ";
		CFSecSecGrpMembBuff buff;
		ArrayList<CFSecSecGrpMembBuff> filteredList = new ArrayList<CFSecSecGrpMembBuff>();
		CFSecSecGrpMembBuff[] buffList = readDerivedByClusterIdx( Authorization,
			ClusterId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a00f" ) ) {
				filteredList.add( (CFSecSecGrpMembBuff)buff );
			}
		}
		return( filteredList.toArray( new CFSecSecGrpMembBuff[0] ) );
	}

	public CFSecSecGrpMembBuff[] readBuffByGroupIdx( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecGroupId )
	{
		final String S_ProcName = "CFSecRamSecGrpMemb.readBuffByGroupIdx() ";
		CFSecSecGrpMembBuff buff;
		ArrayList<CFSecSecGrpMembBuff> filteredList = new ArrayList<CFSecSecGrpMembBuff>();
		CFSecSecGrpMembBuff[] buffList = readDerivedByGroupIdx( Authorization,
			SecGroupId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a00f" ) ) {
				filteredList.add( (CFSecSecGrpMembBuff)buff );
			}
		}
		return( filteredList.toArray( new CFSecSecGrpMembBuff[0] ) );
	}

	public CFSecSecGrpMembBuff[] readBuffByUserIdx( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecUserId )
	{
		final String S_ProcName = "CFSecRamSecGrpMemb.readBuffByUserIdx() ";
		CFSecSecGrpMembBuff buff;
		ArrayList<CFSecSecGrpMembBuff> filteredList = new ArrayList<CFSecSecGrpMembBuff>();
		CFSecSecGrpMembBuff[] buffList = readDerivedByUserIdx( Authorization,
			SecUserId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a00f" ) ) {
				filteredList.add( (CFSecSecGrpMembBuff)buff );
			}
		}
		return( filteredList.toArray( new CFSecSecGrpMembBuff[0] ) );
	}

	public CFSecSecGrpMembBuff readBuffByUUserIdx( CFSecAuthorization Authorization,
		long ClusterId,
		CFLibDbKeyHash256 SecGroupId,
		CFLibDbKeyHash256 SecUserId )
	{
		final String S_ProcName = "CFSecRamSecGrpMemb.readBuffByUUserIdx() ";
		CFSecSecGrpMembBuff buff = readDerivedByUUserIdx( Authorization,
			ClusterId,
			SecGroupId,
			SecUserId );
		if( ( buff != null ) && buff.getClassCode().equals( "a00f" ) ) {
			return( (CFSecSecGrpMembBuff)buff );
		}
		else {
			return( null );
		}
	}

	/**
	 *	Read a page array of the specific SecGrpMemb buffer instances identified by the duplicate key ClusterIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	ClusterId	The SecGrpMemb key attribute of the instance generating the id.
	 *
	 *	@return An array of derived buffer instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	public CFSecSecGrpMembBuff[] pageBuffByClusterIdx( CFSecAuthorization Authorization,
		long ClusterId,
		CFLibDbKeyHash256 priorSecGrpMembId )
	{
		final String S_ProcName = "pageBuffByClusterIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	/**
	 *	Read a page array of the specific SecGrpMemb buffer instances identified by the duplicate key GroupIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	SecGroupId	The SecGrpMemb key attribute of the instance generating the id.
	 *
	 *	@return An array of derived buffer instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	public CFSecSecGrpMembBuff[] pageBuffByGroupIdx( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecGroupId,
		CFLibDbKeyHash256 priorSecGrpMembId )
	{
		final String S_ProcName = "pageBuffByGroupIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	/**
	 *	Read a page array of the specific SecGrpMemb buffer instances identified by the duplicate key UserIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	SecUserId	The SecGrpMemb key attribute of the instance generating the id.
	 *
	 *	@return An array of derived buffer instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	public CFSecSecGrpMembBuff[] pageBuffByUserIdx( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecUserId,
		CFLibDbKeyHash256 priorSecGrpMembId )
	{
		final String S_ProcName = "pageBuffByUserIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	public void updateSecGrpMemb( CFSecAuthorization Authorization,
		CFSecSecGrpMembBuff Buff )
	{
		CFSecSecGrpMembPKey pkey = schema.getFactorySecGrpMemb().newPKey();
		pkey.setRequiredSecGrpMembId( Buff.getRequiredSecGrpMembId() );
		CFSecSecGrpMembBuff existing = dictByPKey.get( pkey );
		if( existing == null ) {
			throw new CFLibStaleCacheDetectedException( getClass(),
				"updateSecGrpMemb",
				"Existing record not found",
				"SecGrpMemb",
				pkey );
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() ) {
			throw new CFLibCollisionDetectedException( getClass(),
				"updateSecGrpMemb",
				pkey );
		}
		Buff.setRequiredRevision( Buff.getRequiredRevision() + 1 );
		CFSecSecGrpMembByClusterIdxKey existingKeyClusterIdx = schema.getFactorySecGrpMemb().newClusterIdxKey();
		existingKeyClusterIdx.setRequiredClusterId( existing.getRequiredClusterId() );

		CFSecSecGrpMembByClusterIdxKey newKeyClusterIdx = schema.getFactorySecGrpMemb().newClusterIdxKey();
		newKeyClusterIdx.setRequiredClusterId( Buff.getRequiredClusterId() );

		CFSecSecGrpMembByGroupIdxKey existingKeyGroupIdx = schema.getFactorySecGrpMemb().newGroupIdxKey();
		existingKeyGroupIdx.setRequiredSecGroupId( existing.getRequiredSecGroupId() );

		CFSecSecGrpMembByGroupIdxKey newKeyGroupIdx = schema.getFactorySecGrpMemb().newGroupIdxKey();
		newKeyGroupIdx.setRequiredSecGroupId( Buff.getRequiredSecGroupId() );

		CFSecSecGrpMembByUserIdxKey existingKeyUserIdx = schema.getFactorySecGrpMemb().newUserIdxKey();
		existingKeyUserIdx.setRequiredSecUserId( existing.getRequiredSecUserId() );

		CFSecSecGrpMembByUserIdxKey newKeyUserIdx = schema.getFactorySecGrpMemb().newUserIdxKey();
		newKeyUserIdx.setRequiredSecUserId( Buff.getRequiredSecUserId() );

		CFSecSecGrpMembByUUserIdxKey existingKeyUUserIdx = schema.getFactorySecGrpMemb().newUUserIdxKey();
		existingKeyUUserIdx.setRequiredClusterId( existing.getRequiredClusterId() );
		existingKeyUUserIdx.setRequiredSecGroupId( existing.getRequiredSecGroupId() );
		existingKeyUUserIdx.setRequiredSecUserId( existing.getRequiredSecUserId() );

		CFSecSecGrpMembByUUserIdxKey newKeyUUserIdx = schema.getFactorySecGrpMemb().newUUserIdxKey();
		newKeyUUserIdx.setRequiredClusterId( Buff.getRequiredClusterId() );
		newKeyUUserIdx.setRequiredSecGroupId( Buff.getRequiredSecGroupId() );
		newKeyUUserIdx.setRequiredSecUserId( Buff.getRequiredSecUserId() );

		// Check unique indexes

		if( ! existingKeyUUserIdx.equals( newKeyUUserIdx ) ) {
			if( dictByUUserIdx.containsKey( newKeyUUserIdx ) ) {
				throw new CFLibUniqueIndexViolationException( getClass(),
					"updateSecGrpMemb",
					"SecGrpMembUUserIdx",
					newKeyUUserIdx );
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
						"updateSecGrpMemb",
						"Owner",
						"SecGrpMembCluster",
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
						"updateSecGrpMemb",
						"Container",
						"SecGrpMembGroup",
						"SecGroup",
						null );
				}
			}
		}

		// Update is valid

		Map< CFSecSecGrpMembPKey, CFSecSecGrpMembBuff > subdict;

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
			subdict = new HashMap< CFSecSecGrpMembPKey, CFSecSecGrpMembBuff >();
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
			subdict = new HashMap< CFSecSecGrpMembPKey, CFSecSecGrpMembBuff >();
			dictByGroupIdx.put( newKeyGroupIdx, subdict );
		}
		subdict.put( pkey, Buff );

		subdict = dictByUserIdx.get( existingKeyUserIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictByUserIdx.containsKey( newKeyUserIdx ) ) {
			subdict = dictByUserIdx.get( newKeyUserIdx );
		}
		else {
			subdict = new HashMap< CFSecSecGrpMembPKey, CFSecSecGrpMembBuff >();
			dictByUserIdx.put( newKeyUserIdx, subdict );
		}
		subdict.put( pkey, Buff );

		dictByUUserIdx.remove( existingKeyUUserIdx );
		dictByUUserIdx.put( newKeyUUserIdx, Buff );

	}

	public void deleteSecGrpMemb( CFSecAuthorization Authorization,
		CFSecSecGrpMembBuff Buff )
	{
		final String S_ProcName = "CFSecRamSecGrpMembTable.deleteSecGrpMemb() ";
		String classCode;
		CFSecSecGrpMembPKey pkey = schema.getFactorySecGrpMemb().newPKey();
		pkey.setRequiredSecGrpMembId( Buff.getRequiredSecGrpMembId() );
		CFSecSecGrpMembBuff existing = dictByPKey.get( pkey );
		if( existing == null ) {
			return;
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() )
		{
			throw new CFLibCollisionDetectedException( getClass(),
				"deleteSecGrpMemb",
				pkey );
		}
		CFSecSecGrpMembByClusterIdxKey keyClusterIdx = schema.getFactorySecGrpMemb().newClusterIdxKey();
		keyClusterIdx.setRequiredClusterId( existing.getRequiredClusterId() );

		CFSecSecGrpMembByGroupIdxKey keyGroupIdx = schema.getFactorySecGrpMemb().newGroupIdxKey();
		keyGroupIdx.setRequiredSecGroupId( existing.getRequiredSecGroupId() );

		CFSecSecGrpMembByUserIdxKey keyUserIdx = schema.getFactorySecGrpMemb().newUserIdxKey();
		keyUserIdx.setRequiredSecUserId( existing.getRequiredSecUserId() );

		CFSecSecGrpMembByUUserIdxKey keyUUserIdx = schema.getFactorySecGrpMemb().newUUserIdxKey();
		keyUUserIdx.setRequiredClusterId( existing.getRequiredClusterId() );
		keyUUserIdx.setRequiredSecGroupId( existing.getRequiredSecGroupId() );
		keyUUserIdx.setRequiredSecUserId( existing.getRequiredSecUserId() );

		// Validate reverse foreign keys

		// Delete is valid
		Map< CFSecSecGrpMembPKey, CFSecSecGrpMembBuff > subdict;

		dictByPKey.remove( pkey );

		subdict = dictByClusterIdx.get( keyClusterIdx );
		subdict.remove( pkey );

		subdict = dictByGroupIdx.get( keyGroupIdx );
		subdict.remove( pkey );

		subdict = dictByUserIdx.get( keyUserIdx );
		subdict.remove( pkey );

		dictByUUserIdx.remove( keyUUserIdx );

	}
	public void deleteSecGrpMembByIdIdx( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 argSecGrpMembId )
	{
		CFSecSecGrpMembPKey key = schema.getFactorySecGrpMemb().newPKey();
		key.setRequiredSecGrpMembId( argSecGrpMembId );
		deleteSecGrpMembByIdIdx( Authorization, key );
	}

	public void deleteSecGrpMembByIdIdx( CFSecAuthorization Authorization,
		CFSecSecGrpMembPKey argKey )
	{
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		CFSecSecGrpMembBuff cur;
		LinkedList<CFSecSecGrpMembBuff> matchSet = new LinkedList<CFSecSecGrpMembBuff>();
		Iterator<CFSecSecGrpMembBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecSecGrpMembBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableSecGrpMemb().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecGrpMembId() );
			deleteSecGrpMemb( Authorization, cur );
		}
	}

	public void deleteSecGrpMembByClusterIdx( CFSecAuthorization Authorization,
		long argClusterId )
	{
		CFSecSecGrpMembByClusterIdxKey key = schema.getFactorySecGrpMemb().newClusterIdxKey();
		key.setRequiredClusterId( argClusterId );
		deleteSecGrpMembByClusterIdx( Authorization, key );
	}

	public void deleteSecGrpMembByClusterIdx( CFSecAuthorization Authorization,
		CFSecSecGrpMembByClusterIdxKey argKey )
	{
		CFSecSecGrpMembBuff cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecSecGrpMembBuff> matchSet = new LinkedList<CFSecSecGrpMembBuff>();
		Iterator<CFSecSecGrpMembBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecSecGrpMembBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableSecGrpMemb().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecGrpMembId() );
			deleteSecGrpMemb( Authorization, cur );
		}
	}

	public void deleteSecGrpMembByGroupIdx( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 argSecGroupId )
	{
		CFSecSecGrpMembByGroupIdxKey key = schema.getFactorySecGrpMemb().newGroupIdxKey();
		key.setRequiredSecGroupId( argSecGroupId );
		deleteSecGrpMembByGroupIdx( Authorization, key );
	}

	public void deleteSecGrpMembByGroupIdx( CFSecAuthorization Authorization,
		CFSecSecGrpMembByGroupIdxKey argKey )
	{
		CFSecSecGrpMembBuff cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecSecGrpMembBuff> matchSet = new LinkedList<CFSecSecGrpMembBuff>();
		Iterator<CFSecSecGrpMembBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecSecGrpMembBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableSecGrpMemb().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecGrpMembId() );
			deleteSecGrpMemb( Authorization, cur );
		}
	}

	public void deleteSecGrpMembByUserIdx( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 argSecUserId )
	{
		CFSecSecGrpMembByUserIdxKey key = schema.getFactorySecGrpMemb().newUserIdxKey();
		key.setRequiredSecUserId( argSecUserId );
		deleteSecGrpMembByUserIdx( Authorization, key );
	}

	public void deleteSecGrpMembByUserIdx( CFSecAuthorization Authorization,
		CFSecSecGrpMembByUserIdxKey argKey )
	{
		CFSecSecGrpMembBuff cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecSecGrpMembBuff> matchSet = new LinkedList<CFSecSecGrpMembBuff>();
		Iterator<CFSecSecGrpMembBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecSecGrpMembBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableSecGrpMemb().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecGrpMembId() );
			deleteSecGrpMemb( Authorization, cur );
		}
	}

	public void deleteSecGrpMembByUUserIdx( CFSecAuthorization Authorization,
		long argClusterId,
		CFLibDbKeyHash256 argSecGroupId,
		CFLibDbKeyHash256 argSecUserId )
	{
		CFSecSecGrpMembByUUserIdxKey key = schema.getFactorySecGrpMemb().newUUserIdxKey();
		key.setRequiredClusterId( argClusterId );
		key.setRequiredSecGroupId( argSecGroupId );
		key.setRequiredSecUserId( argSecUserId );
		deleteSecGrpMembByUUserIdx( Authorization, key );
	}

	public void deleteSecGrpMembByUUserIdx( CFSecAuthorization Authorization,
		CFSecSecGrpMembByUUserIdxKey argKey )
	{
		CFSecSecGrpMembBuff cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecSecGrpMembBuff> matchSet = new LinkedList<CFSecSecGrpMembBuff>();
		Iterator<CFSecSecGrpMembBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecSecGrpMembBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableSecGrpMemb().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecGrpMembId() );
			deleteSecGrpMemb( Authorization, cur );
		}
	}
}
