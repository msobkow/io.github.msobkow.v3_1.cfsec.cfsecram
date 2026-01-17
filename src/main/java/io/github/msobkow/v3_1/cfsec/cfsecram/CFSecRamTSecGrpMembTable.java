
// Description: Java 25 in-memory RAM DbIO implementation for TSecGrpMemb.

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
 *	CFSecRamTSecGrpMembTable in-memory RAM DbIO implementation
 *	for TSecGrpMemb.
 */
public class CFSecRamTSecGrpMembTable
	implements ICFSecTSecGrpMembTable
{
	private ICFSecSchema schema;
	private Map< CFSecTSecGrpMembPKey,
				CFSecTSecGrpMembBuff > dictByPKey
		= new HashMap< CFSecTSecGrpMembPKey,
				CFSecTSecGrpMembBuff >();
	private Map< CFSecTSecGrpMembByTenantIdxKey,
				Map< CFSecTSecGrpMembPKey,
					CFSecTSecGrpMembBuff >> dictByTenantIdx
		= new HashMap< CFSecTSecGrpMembByTenantIdxKey,
				Map< CFSecTSecGrpMembPKey,
					CFSecTSecGrpMembBuff >>();
	private Map< CFSecTSecGrpMembByGroupIdxKey,
				Map< CFSecTSecGrpMembPKey,
					CFSecTSecGrpMembBuff >> dictByGroupIdx
		= new HashMap< CFSecTSecGrpMembByGroupIdxKey,
				Map< CFSecTSecGrpMembPKey,
					CFSecTSecGrpMembBuff >>();
	private Map< CFSecTSecGrpMembByUserIdxKey,
				Map< CFSecTSecGrpMembPKey,
					CFSecTSecGrpMembBuff >> dictByUserIdx
		= new HashMap< CFSecTSecGrpMembByUserIdxKey,
				Map< CFSecTSecGrpMembPKey,
					CFSecTSecGrpMembBuff >>();
	private Map< CFSecTSecGrpMembByUUserIdxKey,
			CFSecTSecGrpMembBuff > dictByUUserIdx
		= new HashMap< CFSecTSecGrpMembByUUserIdxKey,
			CFSecTSecGrpMembBuff >();

	public CFSecRamTSecGrpMembTable( ICFSecSchema argSchema ) {
		schema = argSchema;
	}

	public void createTSecGrpMemb( CFSecAuthorization Authorization,
		CFSecTSecGrpMembBuff Buff )
	{
		final String S_ProcName = "createTSecGrpMemb";
		CFSecTSecGrpMembPKey pkey = schema.getFactoryTSecGrpMemb().newPKey();
		pkey.setRequiredTSecGrpMembId( schema.nextTSecGrpMembIdGen() );
		Buff.setRequiredTSecGrpMembId( pkey.getRequiredTSecGrpMembId() );
		CFSecTSecGrpMembByTenantIdxKey keyTenantIdx = schema.getFactoryTSecGrpMemb().newTenantIdxKey();
		keyTenantIdx.setRequiredTenantId( Buff.getRequiredTenantId() );

		CFSecTSecGrpMembByGroupIdxKey keyGroupIdx = schema.getFactoryTSecGrpMemb().newGroupIdxKey();
		keyGroupIdx.setRequiredTSecGroupId( Buff.getRequiredTSecGroupId() );

		CFSecTSecGrpMembByUserIdxKey keyUserIdx = schema.getFactoryTSecGrpMemb().newUserIdxKey();
		keyUserIdx.setRequiredSecUserId( Buff.getRequiredSecUserId() );

		CFSecTSecGrpMembByUUserIdxKey keyUUserIdx = schema.getFactoryTSecGrpMemb().newUUserIdxKey();
		keyUUserIdx.setRequiredTenantId( Buff.getRequiredTenantId() );
		keyUUserIdx.setRequiredTSecGroupId( Buff.getRequiredTSecGroupId() );
		keyUUserIdx.setRequiredSecUserId( Buff.getRequiredSecUserId() );

		// Validate unique indexes

		if( dictByPKey.containsKey( pkey ) ) {
			throw new CFLibPrimaryKeyNotNewException( getClass(), S_ProcName, pkey );
		}

		if( dictByUUserIdx.containsKey( keyUUserIdx ) ) {
			throw new CFLibUniqueIndexViolationException( getClass(),
				S_ProcName,
				"TSecGrpMembUUserIdx",
				keyUUserIdx );
		}

		// Validate foreign keys

		{
			boolean allNull = true;
			allNull = false;
			if( ! allNull ) {
				if( null == schema.getTableTenant().readDerivedByIdIdx( Authorization,
						Buff.getRequiredTenantId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						S_ProcName,
						"Owner",
						"TSecGrpMembTenant",
						"Tenant",
						null );
				}
			}
		}

		{
			boolean allNull = true;
			allNull = false;
			if( ! allNull ) {
				if( null == schema.getTableTSecGroup().readDerivedByIdIdx( Authorization,
						Buff.getRequiredTSecGroupId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						S_ProcName,
						"Container",
						"TSecGrpMembGroup",
						"TSecGroup",
						null );
				}
			}
		}

		// Proceed with adding the new record

		dictByPKey.put( pkey, Buff );

		Map< CFSecTSecGrpMembPKey, CFSecTSecGrpMembBuff > subdictTenantIdx;
		if( dictByTenantIdx.containsKey( keyTenantIdx ) ) {
			subdictTenantIdx = dictByTenantIdx.get( keyTenantIdx );
		}
		else {
			subdictTenantIdx = new HashMap< CFSecTSecGrpMembPKey, CFSecTSecGrpMembBuff >();
			dictByTenantIdx.put( keyTenantIdx, subdictTenantIdx );
		}
		subdictTenantIdx.put( pkey, Buff );

		Map< CFSecTSecGrpMembPKey, CFSecTSecGrpMembBuff > subdictGroupIdx;
		if( dictByGroupIdx.containsKey( keyGroupIdx ) ) {
			subdictGroupIdx = dictByGroupIdx.get( keyGroupIdx );
		}
		else {
			subdictGroupIdx = new HashMap< CFSecTSecGrpMembPKey, CFSecTSecGrpMembBuff >();
			dictByGroupIdx.put( keyGroupIdx, subdictGroupIdx );
		}
		subdictGroupIdx.put( pkey, Buff );

		Map< CFSecTSecGrpMembPKey, CFSecTSecGrpMembBuff > subdictUserIdx;
		if( dictByUserIdx.containsKey( keyUserIdx ) ) {
			subdictUserIdx = dictByUserIdx.get( keyUserIdx );
		}
		else {
			subdictUserIdx = new HashMap< CFSecTSecGrpMembPKey, CFSecTSecGrpMembBuff >();
			dictByUserIdx.put( keyUserIdx, subdictUserIdx );
		}
		subdictUserIdx.put( pkey, Buff );

		dictByUUserIdx.put( keyUUserIdx, Buff );

	}

	public CFSecTSecGrpMembBuff readDerived( CFSecAuthorization Authorization,
		CFSecTSecGrpMembPKey PKey )
	{
		final String S_ProcName = "CFSecRamTSecGrpMemb.readDerived";
		CFSecTSecGrpMembPKey key = schema.getFactoryTSecGrpMemb().newPKey();
		key.setRequiredTSecGrpMembId( PKey.getRequiredTSecGrpMembId() );
		CFSecTSecGrpMembBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecTSecGrpMembBuff lockDerived( CFSecAuthorization Authorization,
		CFSecTSecGrpMembPKey PKey )
	{
		final String S_ProcName = "CFSecRamTSecGrpMemb.readDerived";
		CFSecTSecGrpMembPKey key = schema.getFactoryTSecGrpMemb().newPKey();
		key.setRequiredTSecGrpMembId( PKey.getRequiredTSecGrpMembId() );
		CFSecTSecGrpMembBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecTSecGrpMembBuff[] readAllDerived( CFSecAuthorization Authorization ) {
		final String S_ProcName = "CFSecRamTSecGrpMemb.readAllDerived";
		CFSecTSecGrpMembBuff[] retList = new CFSecTSecGrpMembBuff[ dictByPKey.values().size() ];
		Iterator< CFSecTSecGrpMembBuff > iter = dictByPKey.values().iterator();
		int idx = 0;
		while( iter.hasNext() ) {
			retList[ idx++ ] = iter.next();
		}
		return( retList );
	}

	public CFSecTSecGrpMembBuff[] readDerivedByTenantIdx( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 TenantId )
	{
		final String S_ProcName = "CFSecRamTSecGrpMemb.readDerivedByTenantIdx";
		CFSecTSecGrpMembByTenantIdxKey key = schema.getFactoryTSecGrpMemb().newTenantIdxKey();
		key.setRequiredTenantId( TenantId );

		CFSecTSecGrpMembBuff[] recArray;
		if( dictByTenantIdx.containsKey( key ) ) {
			Map< CFSecTSecGrpMembPKey, CFSecTSecGrpMembBuff > subdictTenantIdx
				= dictByTenantIdx.get( key );
			recArray = new CFSecTSecGrpMembBuff[ subdictTenantIdx.size() ];
			Iterator< CFSecTSecGrpMembBuff > iter = subdictTenantIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFSecTSecGrpMembPKey, CFSecTSecGrpMembBuff > subdictTenantIdx
				= new HashMap< CFSecTSecGrpMembPKey, CFSecTSecGrpMembBuff >();
			dictByTenantIdx.put( key, subdictTenantIdx );
			recArray = new CFSecTSecGrpMembBuff[0];
		}
		return( recArray );
	}

	public CFSecTSecGrpMembBuff[] readDerivedByGroupIdx( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 TSecGroupId )
	{
		final String S_ProcName = "CFSecRamTSecGrpMemb.readDerivedByGroupIdx";
		CFSecTSecGrpMembByGroupIdxKey key = schema.getFactoryTSecGrpMemb().newGroupIdxKey();
		key.setRequiredTSecGroupId( TSecGroupId );

		CFSecTSecGrpMembBuff[] recArray;
		if( dictByGroupIdx.containsKey( key ) ) {
			Map< CFSecTSecGrpMembPKey, CFSecTSecGrpMembBuff > subdictGroupIdx
				= dictByGroupIdx.get( key );
			recArray = new CFSecTSecGrpMembBuff[ subdictGroupIdx.size() ];
			Iterator< CFSecTSecGrpMembBuff > iter = subdictGroupIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFSecTSecGrpMembPKey, CFSecTSecGrpMembBuff > subdictGroupIdx
				= new HashMap< CFSecTSecGrpMembPKey, CFSecTSecGrpMembBuff >();
			dictByGroupIdx.put( key, subdictGroupIdx );
			recArray = new CFSecTSecGrpMembBuff[0];
		}
		return( recArray );
	}

	public CFSecTSecGrpMembBuff[] readDerivedByUserIdx( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecUserId )
	{
		final String S_ProcName = "CFSecRamTSecGrpMemb.readDerivedByUserIdx";
		CFSecTSecGrpMembByUserIdxKey key = schema.getFactoryTSecGrpMemb().newUserIdxKey();
		key.setRequiredSecUserId( SecUserId );

		CFSecTSecGrpMembBuff[] recArray;
		if( dictByUserIdx.containsKey( key ) ) {
			Map< CFSecTSecGrpMembPKey, CFSecTSecGrpMembBuff > subdictUserIdx
				= dictByUserIdx.get( key );
			recArray = new CFSecTSecGrpMembBuff[ subdictUserIdx.size() ];
			Iterator< CFSecTSecGrpMembBuff > iter = subdictUserIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFSecTSecGrpMembPKey, CFSecTSecGrpMembBuff > subdictUserIdx
				= new HashMap< CFSecTSecGrpMembPKey, CFSecTSecGrpMembBuff >();
			dictByUserIdx.put( key, subdictUserIdx );
			recArray = new CFSecTSecGrpMembBuff[0];
		}
		return( recArray );
	}

	public CFSecTSecGrpMembBuff readDerivedByUUserIdx( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 TenantId,
		CFLibDbKeyHash256 TSecGroupId,
		CFLibDbKeyHash256 SecUserId )
	{
		final String S_ProcName = "CFSecRamTSecGrpMemb.readDerivedByUUserIdx";
		CFSecTSecGrpMembByUUserIdxKey key = schema.getFactoryTSecGrpMemb().newUUserIdxKey();
		key.setRequiredTenantId( TenantId );
		key.setRequiredTSecGroupId( TSecGroupId );
		key.setRequiredSecUserId( SecUserId );

		CFSecTSecGrpMembBuff buff;
		if( dictByUUserIdx.containsKey( key ) ) {
			buff = dictByUUserIdx.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecTSecGrpMembBuff readDerivedByIdIdx( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 TSecGrpMembId )
	{
		final String S_ProcName = "CFSecRamTSecGrpMemb.readDerivedByIdIdx() ";
		CFSecTSecGrpMembPKey key = schema.getFactoryTSecGrpMemb().newPKey();
		key.setRequiredTSecGrpMembId( TSecGrpMembId );

		CFSecTSecGrpMembBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecTSecGrpMembBuff readBuff( CFSecAuthorization Authorization,
		CFSecTSecGrpMembPKey PKey )
	{
		final String S_ProcName = "CFSecRamTSecGrpMemb.readBuff";
		CFSecTSecGrpMembBuff buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( ! buff.getClassCode().equals( "a018" ) ) ) {
			buff = null;
		}
		return( buff );
	}

	public CFSecTSecGrpMembBuff lockBuff( CFSecAuthorization Authorization,
		CFSecTSecGrpMembPKey PKey )
	{
		final String S_ProcName = "lockBuff";
		CFSecTSecGrpMembBuff buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( ! buff.getClassCode().equals( "a018" ) ) ) {
			buff = null;
		}
		return( buff );
	}

	public CFSecTSecGrpMembBuff[] readAllBuff( CFSecAuthorization Authorization )
	{
		final String S_ProcName = "CFSecRamTSecGrpMemb.readAllBuff";
		CFSecTSecGrpMembBuff buff;
		ArrayList<CFSecTSecGrpMembBuff> filteredList = new ArrayList<CFSecTSecGrpMembBuff>();
		CFSecTSecGrpMembBuff[] buffList = readAllDerived( Authorization );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a018" ) ) {
				filteredList.add( buff );
			}
		}
		return( filteredList.toArray( new CFSecTSecGrpMembBuff[0] ) );
	}

	/**
	 *	Read a page of all the specific TSecGrpMemb buffer instances.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@return All the specific TSecGrpMemb instances in the database accessible for the Authorization.
	 */
	public CFSecTSecGrpMembBuff[] pageAllBuff( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 priorTSecGrpMembId )
	{
		final String S_ProcName = "pageAllBuff";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	public CFSecTSecGrpMembBuff readBuffByIdIdx( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 TSecGrpMembId )
	{
		final String S_ProcName = "CFSecRamTSecGrpMemb.readBuffByIdIdx() ";
		CFSecTSecGrpMembBuff buff = readDerivedByIdIdx( Authorization,
			TSecGrpMembId );
		if( ( buff != null ) && buff.getClassCode().equals( "a018" ) ) {
			return( (CFSecTSecGrpMembBuff)buff );
		}
		else {
			return( null );
		}
	}

	public CFSecTSecGrpMembBuff[] readBuffByTenantIdx( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 TenantId )
	{
		final String S_ProcName = "CFSecRamTSecGrpMemb.readBuffByTenantIdx() ";
		CFSecTSecGrpMembBuff buff;
		ArrayList<CFSecTSecGrpMembBuff> filteredList = new ArrayList<CFSecTSecGrpMembBuff>();
		CFSecTSecGrpMembBuff[] buffList = readDerivedByTenantIdx( Authorization,
			TenantId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a018" ) ) {
				filteredList.add( (CFSecTSecGrpMembBuff)buff );
			}
		}
		return( filteredList.toArray( new CFSecTSecGrpMembBuff[0] ) );
	}

	public CFSecTSecGrpMembBuff[] readBuffByGroupIdx( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 TSecGroupId )
	{
		final String S_ProcName = "CFSecRamTSecGrpMemb.readBuffByGroupIdx() ";
		CFSecTSecGrpMembBuff buff;
		ArrayList<CFSecTSecGrpMembBuff> filteredList = new ArrayList<CFSecTSecGrpMembBuff>();
		CFSecTSecGrpMembBuff[] buffList = readDerivedByGroupIdx( Authorization,
			TSecGroupId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a018" ) ) {
				filteredList.add( (CFSecTSecGrpMembBuff)buff );
			}
		}
		return( filteredList.toArray( new CFSecTSecGrpMembBuff[0] ) );
	}

	public CFSecTSecGrpMembBuff[] readBuffByUserIdx( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecUserId )
	{
		final String S_ProcName = "CFSecRamTSecGrpMemb.readBuffByUserIdx() ";
		CFSecTSecGrpMembBuff buff;
		ArrayList<CFSecTSecGrpMembBuff> filteredList = new ArrayList<CFSecTSecGrpMembBuff>();
		CFSecTSecGrpMembBuff[] buffList = readDerivedByUserIdx( Authorization,
			SecUserId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a018" ) ) {
				filteredList.add( (CFSecTSecGrpMembBuff)buff );
			}
		}
		return( filteredList.toArray( new CFSecTSecGrpMembBuff[0] ) );
	}

	public CFSecTSecGrpMembBuff readBuffByUUserIdx( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 TenantId,
		CFLibDbKeyHash256 TSecGroupId,
		CFLibDbKeyHash256 SecUserId )
	{
		final String S_ProcName = "CFSecRamTSecGrpMemb.readBuffByUUserIdx() ";
		CFSecTSecGrpMembBuff buff = readDerivedByUUserIdx( Authorization,
			TenantId,
			TSecGroupId,
			SecUserId );
		if( ( buff != null ) && buff.getClassCode().equals( "a018" ) ) {
			return( (CFSecTSecGrpMembBuff)buff );
		}
		else {
			return( null );
		}
	}

	/**
	 *	Read a page array of the specific TSecGrpMemb buffer instances identified by the duplicate key TenantIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	TenantId	The TSecGrpMemb key attribute of the instance generating the id.
	 *
	 *	@return An array of derived buffer instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	public CFSecTSecGrpMembBuff[] pageBuffByTenantIdx( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 TenantId,
		CFLibDbKeyHash256 priorTSecGrpMembId )
	{
		final String S_ProcName = "pageBuffByTenantIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	/**
	 *	Read a page array of the specific TSecGrpMemb buffer instances identified by the duplicate key GroupIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	TSecGroupId	The TSecGrpMemb key attribute of the instance generating the id.
	 *
	 *	@return An array of derived buffer instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	public CFSecTSecGrpMembBuff[] pageBuffByGroupIdx( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 TSecGroupId,
		CFLibDbKeyHash256 priorTSecGrpMembId )
	{
		final String S_ProcName = "pageBuffByGroupIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	/**
	 *	Read a page array of the specific TSecGrpMemb buffer instances identified by the duplicate key UserIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	SecUserId	The TSecGrpMemb key attribute of the instance generating the id.
	 *
	 *	@return An array of derived buffer instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	public CFSecTSecGrpMembBuff[] pageBuffByUserIdx( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecUserId,
		CFLibDbKeyHash256 priorTSecGrpMembId )
	{
		final String S_ProcName = "pageBuffByUserIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	public void updateTSecGrpMemb( CFSecAuthorization Authorization,
		CFSecTSecGrpMembBuff Buff )
	{
		CFSecTSecGrpMembPKey pkey = schema.getFactoryTSecGrpMemb().newPKey();
		pkey.setRequiredTSecGrpMembId( Buff.getRequiredTSecGrpMembId() );
		CFSecTSecGrpMembBuff existing = dictByPKey.get( pkey );
		if( existing == null ) {
			throw new CFLibStaleCacheDetectedException( getClass(),
				"updateTSecGrpMemb",
				"Existing record not found",
				"TSecGrpMemb",
				pkey );
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() ) {
			throw new CFLibCollisionDetectedException( getClass(),
				"updateTSecGrpMemb",
				pkey );
		}
		Buff.setRequiredRevision( Buff.getRequiredRevision() + 1 );
		CFSecTSecGrpMembByTenantIdxKey existingKeyTenantIdx = schema.getFactoryTSecGrpMemb().newTenantIdxKey();
		existingKeyTenantIdx.setRequiredTenantId( existing.getRequiredTenantId() );

		CFSecTSecGrpMembByTenantIdxKey newKeyTenantIdx = schema.getFactoryTSecGrpMemb().newTenantIdxKey();
		newKeyTenantIdx.setRequiredTenantId( Buff.getRequiredTenantId() );

		CFSecTSecGrpMembByGroupIdxKey existingKeyGroupIdx = schema.getFactoryTSecGrpMemb().newGroupIdxKey();
		existingKeyGroupIdx.setRequiredTSecGroupId( existing.getRequiredTSecGroupId() );

		CFSecTSecGrpMembByGroupIdxKey newKeyGroupIdx = schema.getFactoryTSecGrpMemb().newGroupIdxKey();
		newKeyGroupIdx.setRequiredTSecGroupId( Buff.getRequiredTSecGroupId() );

		CFSecTSecGrpMembByUserIdxKey existingKeyUserIdx = schema.getFactoryTSecGrpMemb().newUserIdxKey();
		existingKeyUserIdx.setRequiredSecUserId( existing.getRequiredSecUserId() );

		CFSecTSecGrpMembByUserIdxKey newKeyUserIdx = schema.getFactoryTSecGrpMemb().newUserIdxKey();
		newKeyUserIdx.setRequiredSecUserId( Buff.getRequiredSecUserId() );

		CFSecTSecGrpMembByUUserIdxKey existingKeyUUserIdx = schema.getFactoryTSecGrpMemb().newUUserIdxKey();
		existingKeyUUserIdx.setRequiredTenantId( existing.getRequiredTenantId() );
		existingKeyUUserIdx.setRequiredTSecGroupId( existing.getRequiredTSecGroupId() );
		existingKeyUUserIdx.setRequiredSecUserId( existing.getRequiredSecUserId() );

		CFSecTSecGrpMembByUUserIdxKey newKeyUUserIdx = schema.getFactoryTSecGrpMemb().newUUserIdxKey();
		newKeyUUserIdx.setRequiredTenantId( Buff.getRequiredTenantId() );
		newKeyUUserIdx.setRequiredTSecGroupId( Buff.getRequiredTSecGroupId() );
		newKeyUUserIdx.setRequiredSecUserId( Buff.getRequiredSecUserId() );

		// Check unique indexes

		if( ! existingKeyUUserIdx.equals( newKeyUUserIdx ) ) {
			if( dictByUUserIdx.containsKey( newKeyUUserIdx ) ) {
				throw new CFLibUniqueIndexViolationException( getClass(),
					"updateTSecGrpMemb",
					"TSecGrpMembUUserIdx",
					newKeyUUserIdx );
			}
		}

		// Validate foreign keys

		{
			boolean allNull = true;

			if( allNull ) {
				if( null == schema.getTableTenant().readDerivedByIdIdx( Authorization,
						Buff.getRequiredTenantId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						"updateTSecGrpMemb",
						"Owner",
						"TSecGrpMembTenant",
						"Tenant",
						null );
				}
			}
		}

		{
			boolean allNull = true;

			if( allNull ) {
				if( null == schema.getTableTSecGroup().readDerivedByIdIdx( Authorization,
						Buff.getRequiredTSecGroupId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						"updateTSecGrpMemb",
						"Container",
						"TSecGrpMembGroup",
						"TSecGroup",
						null );
				}
			}
		}

		// Update is valid

		Map< CFSecTSecGrpMembPKey, CFSecTSecGrpMembBuff > subdict;

		dictByPKey.remove( pkey );
		dictByPKey.put( pkey, Buff );

		subdict = dictByTenantIdx.get( existingKeyTenantIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictByTenantIdx.containsKey( newKeyTenantIdx ) ) {
			subdict = dictByTenantIdx.get( newKeyTenantIdx );
		}
		else {
			subdict = new HashMap< CFSecTSecGrpMembPKey, CFSecTSecGrpMembBuff >();
			dictByTenantIdx.put( newKeyTenantIdx, subdict );
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
			subdict = new HashMap< CFSecTSecGrpMembPKey, CFSecTSecGrpMembBuff >();
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
			subdict = new HashMap< CFSecTSecGrpMembPKey, CFSecTSecGrpMembBuff >();
			dictByUserIdx.put( newKeyUserIdx, subdict );
		}
		subdict.put( pkey, Buff );

		dictByUUserIdx.remove( existingKeyUUserIdx );
		dictByUUserIdx.put( newKeyUUserIdx, Buff );

	}

	public void deleteTSecGrpMemb( CFSecAuthorization Authorization,
		CFSecTSecGrpMembBuff Buff )
	{
		final String S_ProcName = "CFSecRamTSecGrpMembTable.deleteTSecGrpMemb() ";
		String classCode;
		CFSecTSecGrpMembPKey pkey = schema.getFactoryTSecGrpMemb().newPKey();
		pkey.setRequiredTSecGrpMembId( Buff.getRequiredTSecGrpMembId() );
		CFSecTSecGrpMembBuff existing = dictByPKey.get( pkey );
		if( existing == null ) {
			return;
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() )
		{
			throw new CFLibCollisionDetectedException( getClass(),
				"deleteTSecGrpMemb",
				pkey );
		}
		CFSecTSecGrpMembByTenantIdxKey keyTenantIdx = schema.getFactoryTSecGrpMemb().newTenantIdxKey();
		keyTenantIdx.setRequiredTenantId( existing.getRequiredTenantId() );

		CFSecTSecGrpMembByGroupIdxKey keyGroupIdx = schema.getFactoryTSecGrpMemb().newGroupIdxKey();
		keyGroupIdx.setRequiredTSecGroupId( existing.getRequiredTSecGroupId() );

		CFSecTSecGrpMembByUserIdxKey keyUserIdx = schema.getFactoryTSecGrpMemb().newUserIdxKey();
		keyUserIdx.setRequiredSecUserId( existing.getRequiredSecUserId() );

		CFSecTSecGrpMembByUUserIdxKey keyUUserIdx = schema.getFactoryTSecGrpMemb().newUUserIdxKey();
		keyUUserIdx.setRequiredTenantId( existing.getRequiredTenantId() );
		keyUUserIdx.setRequiredTSecGroupId( existing.getRequiredTSecGroupId() );
		keyUUserIdx.setRequiredSecUserId( existing.getRequiredSecUserId() );

		// Validate reverse foreign keys

		// Delete is valid
		Map< CFSecTSecGrpMembPKey, CFSecTSecGrpMembBuff > subdict;

		dictByPKey.remove( pkey );

		subdict = dictByTenantIdx.get( keyTenantIdx );
		subdict.remove( pkey );

		subdict = dictByGroupIdx.get( keyGroupIdx );
		subdict.remove( pkey );

		subdict = dictByUserIdx.get( keyUserIdx );
		subdict.remove( pkey );

		dictByUUserIdx.remove( keyUUserIdx );

	}
	public void deleteTSecGrpMembByIdIdx( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 argTSecGrpMembId )
	{
		CFSecTSecGrpMembPKey key = schema.getFactoryTSecGrpMemb().newPKey();
		key.setRequiredTSecGrpMembId( argTSecGrpMembId );
		deleteTSecGrpMembByIdIdx( Authorization, key );
	}

	public void deleteTSecGrpMembByIdIdx( CFSecAuthorization Authorization,
		CFSecTSecGrpMembPKey argKey )
	{
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		CFSecTSecGrpMembBuff cur;
		LinkedList<CFSecTSecGrpMembBuff> matchSet = new LinkedList<CFSecTSecGrpMembBuff>();
		Iterator<CFSecTSecGrpMembBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecTSecGrpMembBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableTSecGrpMemb().readDerivedByIdIdx( Authorization,
				cur.getRequiredTSecGrpMembId() );
			deleteTSecGrpMemb( Authorization, cur );
		}
	}

	public void deleteTSecGrpMembByTenantIdx( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 argTenantId )
	{
		CFSecTSecGrpMembByTenantIdxKey key = schema.getFactoryTSecGrpMemb().newTenantIdxKey();
		key.setRequiredTenantId( argTenantId );
		deleteTSecGrpMembByTenantIdx( Authorization, key );
	}

	public void deleteTSecGrpMembByTenantIdx( CFSecAuthorization Authorization,
		CFSecTSecGrpMembByTenantIdxKey argKey )
	{
		CFSecTSecGrpMembBuff cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecTSecGrpMembBuff> matchSet = new LinkedList<CFSecTSecGrpMembBuff>();
		Iterator<CFSecTSecGrpMembBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecTSecGrpMembBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableTSecGrpMemb().readDerivedByIdIdx( Authorization,
				cur.getRequiredTSecGrpMembId() );
			deleteTSecGrpMemb( Authorization, cur );
		}
	}

	public void deleteTSecGrpMembByGroupIdx( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 argTSecGroupId )
	{
		CFSecTSecGrpMembByGroupIdxKey key = schema.getFactoryTSecGrpMemb().newGroupIdxKey();
		key.setRequiredTSecGroupId( argTSecGroupId );
		deleteTSecGrpMembByGroupIdx( Authorization, key );
	}

	public void deleteTSecGrpMembByGroupIdx( CFSecAuthorization Authorization,
		CFSecTSecGrpMembByGroupIdxKey argKey )
	{
		CFSecTSecGrpMembBuff cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecTSecGrpMembBuff> matchSet = new LinkedList<CFSecTSecGrpMembBuff>();
		Iterator<CFSecTSecGrpMembBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecTSecGrpMembBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableTSecGrpMemb().readDerivedByIdIdx( Authorization,
				cur.getRequiredTSecGrpMembId() );
			deleteTSecGrpMemb( Authorization, cur );
		}
	}

	public void deleteTSecGrpMembByUserIdx( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 argSecUserId )
	{
		CFSecTSecGrpMembByUserIdxKey key = schema.getFactoryTSecGrpMemb().newUserIdxKey();
		key.setRequiredSecUserId( argSecUserId );
		deleteTSecGrpMembByUserIdx( Authorization, key );
	}

	public void deleteTSecGrpMembByUserIdx( CFSecAuthorization Authorization,
		CFSecTSecGrpMembByUserIdxKey argKey )
	{
		CFSecTSecGrpMembBuff cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecTSecGrpMembBuff> matchSet = new LinkedList<CFSecTSecGrpMembBuff>();
		Iterator<CFSecTSecGrpMembBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecTSecGrpMembBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableTSecGrpMemb().readDerivedByIdIdx( Authorization,
				cur.getRequiredTSecGrpMembId() );
			deleteTSecGrpMemb( Authorization, cur );
		}
	}

	public void deleteTSecGrpMembByUUserIdx( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 argTenantId,
		CFLibDbKeyHash256 argTSecGroupId,
		CFLibDbKeyHash256 argSecUserId )
	{
		CFSecTSecGrpMembByUUserIdxKey key = schema.getFactoryTSecGrpMemb().newUUserIdxKey();
		key.setRequiredTenantId( argTenantId );
		key.setRequiredTSecGroupId( argTSecGroupId );
		key.setRequiredSecUserId( argSecUserId );
		deleteTSecGrpMembByUUserIdx( Authorization, key );
	}

	public void deleteTSecGrpMembByUUserIdx( CFSecAuthorization Authorization,
		CFSecTSecGrpMembByUUserIdxKey argKey )
	{
		CFSecTSecGrpMembBuff cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecTSecGrpMembBuff> matchSet = new LinkedList<CFSecTSecGrpMembBuff>();
		Iterator<CFSecTSecGrpMembBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecTSecGrpMembBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableTSecGrpMemb().readDerivedByIdIdx( Authorization,
				cur.getRequiredTSecGrpMembId() );
			deleteTSecGrpMemb( Authorization, cur );
		}
	}
}
