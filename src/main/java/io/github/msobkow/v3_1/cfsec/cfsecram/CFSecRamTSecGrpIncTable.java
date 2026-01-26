
// Description: Java 25 in-memory RAM DbIO implementation for TSecGrpInc.

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
 *	CFSecRamTSecGrpIncTable in-memory RAM DbIO implementation
 *	for TSecGrpInc.
 */
public class CFSecRamTSecGrpIncTable
	implements ICFSecTSecGrpIncTable
{
	private ICFSecSchema schema;
	private Map< CFLibDbKeyHash256,
				CFSecBuffTSecGrpInc > dictByPKey
		= new HashMap< CFLibDbKeyHash256,
				CFSecBuffTSecGrpInc >();
	private Map< CFSecBuffTSecGrpIncByTenantIdxKey,
				Map< CFLibDbKeyHash256,
					CFSecBuffTSecGrpInc >> dictByTenantIdx
		= new HashMap< CFSecBuffTSecGrpIncByTenantIdxKey,
				Map< CFLibDbKeyHash256,
					CFSecBuffTSecGrpInc >>();
	private Map< CFSecBuffTSecGrpIncByGroupIdxKey,
				Map< CFLibDbKeyHash256,
					CFSecBuffTSecGrpInc >> dictByGroupIdx
		= new HashMap< CFSecBuffTSecGrpIncByGroupIdxKey,
				Map< CFLibDbKeyHash256,
					CFSecBuffTSecGrpInc >>();
	private Map< CFSecBuffTSecGrpIncByIncludeIdxKey,
				Map< CFLibDbKeyHash256,
					CFSecBuffTSecGrpInc >> dictByIncludeIdx
		= new HashMap< CFSecBuffTSecGrpIncByIncludeIdxKey,
				Map< CFLibDbKeyHash256,
					CFSecBuffTSecGrpInc >>();
	private Map< CFSecBuffTSecGrpIncByUIncludeIdxKey,
			CFSecBuffTSecGrpInc > dictByUIncludeIdx
		= new HashMap< CFSecBuffTSecGrpIncByUIncludeIdxKey,
			CFSecBuffTSecGrpInc >();

	public CFSecRamTSecGrpIncTable( ICFSecSchema argSchema ) {
		schema = argSchema;
	}

	public void createTSecGrpInc( ICFSecAuthorization Authorization,
		ICFSecTSecGrpInc Buff )
	{
		final String S_ProcName = "createTSecGrpInc";
		CFLibDbKeyHash256 pkey = schema.getFactoryTSecGrpInc().newPKey();
		pkey.setRequiredTSecGrpIncId( schema.nextTSecGrpIncIdGen() );
		Buff.setRequiredTSecGrpIncId( pkey.getRequiredTSecGrpIncId() );
		CFSecBuffTSecGrpIncByTenantIdxKey keyTenantIdx = schema.getFactoryTSecGrpInc().newTenantIdxKey();
		keyTenantIdx.setRequiredTenantId( Buff.getRequiredTenantId() );

		CFSecBuffTSecGrpIncByGroupIdxKey keyGroupIdx = schema.getFactoryTSecGrpInc().newGroupIdxKey();
		keyGroupIdx.setRequiredTSecGroupId( Buff.getRequiredTSecGroupId() );

		CFSecBuffTSecGrpIncByIncludeIdxKey keyIncludeIdx = schema.getFactoryTSecGrpInc().newIncludeIdxKey();
		keyIncludeIdx.setRequiredIncludeGroupId( Buff.getRequiredIncludeGroupId() );

		CFSecBuffTSecGrpIncByUIncludeIdxKey keyUIncludeIdx = schema.getFactoryTSecGrpInc().newUIncludeIdxKey();
		keyUIncludeIdx.setRequiredTenantId( Buff.getRequiredTenantId() );
		keyUIncludeIdx.setRequiredTSecGroupId( Buff.getRequiredTSecGroupId() );
		keyUIncludeIdx.setRequiredIncludeGroupId( Buff.getRequiredIncludeGroupId() );

		// Validate unique indexes

		if( dictByPKey.containsKey( pkey ) ) {
			throw new CFLibPrimaryKeyNotNewException( getClass(), S_ProcName, pkey );
		}

		if( dictByUIncludeIdx.containsKey( keyUIncludeIdx ) ) {
			throw new CFLibUniqueIndexViolationException( getClass(),
				S_ProcName,
				"TSecGrpIncUIncludeIdx",
				keyUIncludeIdx );
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
						"TSecGrpIncTenant",
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
						"TSecGrpIncGroup",
						"TSecGroup",
						null );
				}
			}
		}

		// Proceed with adding the new record

		dictByPKey.put( pkey, Buff );

		Map< CFLibDbKeyHash256, CFSecBuffTSecGrpInc > subdictTenantIdx;
		if( dictByTenantIdx.containsKey( keyTenantIdx ) ) {
			subdictTenantIdx = dictByTenantIdx.get( keyTenantIdx );
		}
		else {
			subdictTenantIdx = new HashMap< CFLibDbKeyHash256, CFSecBuffTSecGrpInc >();
			dictByTenantIdx.put( keyTenantIdx, subdictTenantIdx );
		}
		subdictTenantIdx.put( pkey, Buff );

		Map< CFLibDbKeyHash256, CFSecBuffTSecGrpInc > subdictGroupIdx;
		if( dictByGroupIdx.containsKey( keyGroupIdx ) ) {
			subdictGroupIdx = dictByGroupIdx.get( keyGroupIdx );
		}
		else {
			subdictGroupIdx = new HashMap< CFLibDbKeyHash256, CFSecBuffTSecGrpInc >();
			dictByGroupIdx.put( keyGroupIdx, subdictGroupIdx );
		}
		subdictGroupIdx.put( pkey, Buff );

		Map< CFLibDbKeyHash256, CFSecBuffTSecGrpInc > subdictIncludeIdx;
		if( dictByIncludeIdx.containsKey( keyIncludeIdx ) ) {
			subdictIncludeIdx = dictByIncludeIdx.get( keyIncludeIdx );
		}
		else {
			subdictIncludeIdx = new HashMap< CFLibDbKeyHash256, CFSecBuffTSecGrpInc >();
			dictByIncludeIdx.put( keyIncludeIdx, subdictIncludeIdx );
		}
		subdictIncludeIdx.put( pkey, Buff );

		dictByUIncludeIdx.put( keyUIncludeIdx, Buff );

	}

	public ICFSecTSecGrpInc readDerived( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 PKey )
	{
		final String S_ProcName = "CFSecRamTSecGrpInc.readDerived";
		ICFSecTSecGrpInc buff;
		if( dictByPKey.containsKey( PKey ) ) {
			buff = dictByPKey.get( PKey );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public ICFSecTSecGrpInc lockDerived( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 PKey )
	{
		final String S_ProcName = "CFSecRamTSecGrpInc.readDerived";
		CFLibDbKeyHash256 key = schema.getFactoryTSecGrpInc().newPKey();
		key.setRequiredTSecGrpIncId( PKey.getRequiredTSecGrpIncId() );
		ICFSecTSecGrpInc buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public ICFSecTSecGrpInc[] readAllDerived( ICFSecAuthorization Authorization ) {
		final String S_ProcName = "CFSecRamTSecGrpInc.readAllDerived";
		ICFSecTSecGrpInc[] retList = new ICFSecTSecGrpInc[ dictByPKey.values().size() ];
		Iterator< ICFSecTSecGrpInc > iter = dictByPKey.values().iterator();
		int idx = 0;
		while( iter.hasNext() ) {
			retList[ idx++ ] = iter.next();
		}
		return( retList );
	}

	public ICFSecTSecGrpInc[] readDerivedByTenantIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 TenantId )
	{
		final String S_ProcName = "CFSecRamTSecGrpInc.readDerivedByTenantIdx";
		CFSecBuffTSecGrpIncByTenantIdxKey key = schema.getFactoryTSecGrpInc().newTenantIdxKey();
		key.setRequiredTenantId( TenantId );

		ICFSecTSecGrpInc[] recArray;
		if( dictByTenantIdx.containsKey( key ) ) {
			Map< CFLibDbKeyHash256, CFSecBuffTSecGrpInc > subdictTenantIdx
				= dictByTenantIdx.get( key );
			recArray = new ICFSecTSecGrpInc[ subdictTenantIdx.size() ];
			Iterator< ICFSecTSecGrpInc > iter = subdictTenantIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFLibDbKeyHash256, CFSecBuffTSecGrpInc > subdictTenantIdx
				= new HashMap< CFLibDbKeyHash256, CFSecBuffTSecGrpInc >();
			dictByTenantIdx.put( key, subdictTenantIdx );
			recArray = new ICFSecTSecGrpInc[0];
		}
		return( recArray );
	}

	public ICFSecTSecGrpInc[] readDerivedByGroupIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 TSecGroupId )
	{
		final String S_ProcName = "CFSecRamTSecGrpInc.readDerivedByGroupIdx";
		CFSecBuffTSecGrpIncByGroupIdxKey key = schema.getFactoryTSecGrpInc().newGroupIdxKey();
		key.setRequiredTSecGroupId( TSecGroupId );

		ICFSecTSecGrpInc[] recArray;
		if( dictByGroupIdx.containsKey( key ) ) {
			Map< CFLibDbKeyHash256, CFSecBuffTSecGrpInc > subdictGroupIdx
				= dictByGroupIdx.get( key );
			recArray = new ICFSecTSecGrpInc[ subdictGroupIdx.size() ];
			Iterator< ICFSecTSecGrpInc > iter = subdictGroupIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFLibDbKeyHash256, CFSecBuffTSecGrpInc > subdictGroupIdx
				= new HashMap< CFLibDbKeyHash256, CFSecBuffTSecGrpInc >();
			dictByGroupIdx.put( key, subdictGroupIdx );
			recArray = new ICFSecTSecGrpInc[0];
		}
		return( recArray );
	}

	public ICFSecTSecGrpInc[] readDerivedByIncludeIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 IncludeGroupId )
	{
		final String S_ProcName = "CFSecRamTSecGrpInc.readDerivedByIncludeIdx";
		CFSecBuffTSecGrpIncByIncludeIdxKey key = schema.getFactoryTSecGrpInc().newIncludeIdxKey();
		key.setRequiredIncludeGroupId( IncludeGroupId );

		ICFSecTSecGrpInc[] recArray;
		if( dictByIncludeIdx.containsKey( key ) ) {
			Map< CFLibDbKeyHash256, CFSecBuffTSecGrpInc > subdictIncludeIdx
				= dictByIncludeIdx.get( key );
			recArray = new ICFSecTSecGrpInc[ subdictIncludeIdx.size() ];
			Iterator< ICFSecTSecGrpInc > iter = subdictIncludeIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFLibDbKeyHash256, CFSecBuffTSecGrpInc > subdictIncludeIdx
				= new HashMap< CFLibDbKeyHash256, CFSecBuffTSecGrpInc >();
			dictByIncludeIdx.put( key, subdictIncludeIdx );
			recArray = new ICFSecTSecGrpInc[0];
		}
		return( recArray );
	}

	public ICFSecTSecGrpInc readDerivedByUIncludeIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 TenantId,
		CFLibDbKeyHash256 TSecGroupId,
		CFLibDbKeyHash256 IncludeGroupId )
	{
		final String S_ProcName = "CFSecRamTSecGrpInc.readDerivedByUIncludeIdx";
		CFSecBuffTSecGrpIncByUIncludeIdxKey key = schema.getFactoryTSecGrpInc().newUIncludeIdxKey();
		key.setRequiredTenantId( TenantId );
		key.setRequiredTSecGroupId( TSecGroupId );
		key.setRequiredIncludeGroupId( IncludeGroupId );

		ICFSecTSecGrpInc buff;
		if( dictByUIncludeIdx.containsKey( key ) ) {
			buff = dictByUIncludeIdx.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public ICFSecTSecGrpInc readDerivedByIdIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 TSecGrpIncId )
	{
		final String S_ProcName = "CFSecRamTSecGrpInc.readDerivedByIdIdx() ";
		CFLibDbKeyHash256 key = schema.getFactoryTSecGrpInc().newPKey();
		key.setRequiredTSecGrpIncId( TSecGrpIncId );

		ICFSecTSecGrpInc buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public ICFSecTSecGrpInc readBuff( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 PKey )
	{
		final String S_ProcName = "CFSecRamTSecGrpInc.readBuff";
		ICFSecTSecGrpInc buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( ! buff.getClassCode().equals( "a017" ) ) ) {
			buff = null;
		}
		return( buff );
	}

	public ICFSecTSecGrpInc lockBuff( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 PKey )
	{
		final String S_ProcName = "lockBuff";
		ICFSecTSecGrpInc buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( ! buff.getClassCode().equals( "a017" ) ) ) {
			buff = null;
		}
		return( buff );
	}

	public ICFSecTSecGrpInc[] readAllBuff( ICFSecAuthorization Authorization )
	{
		final String S_ProcName = "CFSecRamTSecGrpInc.readAllBuff";
		ICFSecTSecGrpInc buff;
		ArrayList<ICFSecTSecGrpInc> filteredList = new ArrayList<ICFSecTSecGrpInc>();
		ICFSecTSecGrpInc[] buffList = readAllDerived( Authorization );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a017" ) ) {
				filteredList.add( buff );
			}
		}
		return( filteredList.toArray( new ICFSecTSecGrpInc[0] ) );
	}

	/**
	 *	Read a page of all the specific TSecGrpInc buffer instances.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@return All the specific TSecGrpInc instances in the database accessible for the Authorization.
	 */
	public ICFSecTSecGrpInc[] pageAllBuff( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 priorTSecGrpIncId )
	{
		final String S_ProcName = "pageAllBuff";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	public ICFSecTSecGrpInc readBuffByIdIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 TSecGrpIncId )
	{
		final String S_ProcName = "CFSecRamTSecGrpInc.readBuffByIdIdx() ";
		ICFSecTSecGrpInc buff = readDerivedByIdIdx( Authorization,
			TSecGrpIncId );
		if( ( buff != null ) && buff.getClassCode().equals( "a017" ) ) {
			return( (ICFSecTSecGrpInc)buff );
		}
		else {
			return( null );
		}
	}

	public ICFSecTSecGrpInc[] readBuffByTenantIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 TenantId )
	{
		final String S_ProcName = "CFSecRamTSecGrpInc.readBuffByTenantIdx() ";
		ICFSecTSecGrpInc buff;
		ArrayList<ICFSecTSecGrpInc> filteredList = new ArrayList<ICFSecTSecGrpInc>();
		ICFSecTSecGrpInc[] buffList = readDerivedByTenantIdx( Authorization,
			TenantId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a017" ) ) {
				filteredList.add( (ICFSecTSecGrpInc)buff );
			}
		}
		return( filteredList.toArray( new ICFSecTSecGrpInc[0] ) );
	}

	public ICFSecTSecGrpInc[] readBuffByGroupIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 TSecGroupId )
	{
		final String S_ProcName = "CFSecRamTSecGrpInc.readBuffByGroupIdx() ";
		ICFSecTSecGrpInc buff;
		ArrayList<ICFSecTSecGrpInc> filteredList = new ArrayList<ICFSecTSecGrpInc>();
		ICFSecTSecGrpInc[] buffList = readDerivedByGroupIdx( Authorization,
			TSecGroupId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a017" ) ) {
				filteredList.add( (ICFSecTSecGrpInc)buff );
			}
		}
		return( filteredList.toArray( new ICFSecTSecGrpInc[0] ) );
	}

	public ICFSecTSecGrpInc[] readBuffByIncludeIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 IncludeGroupId )
	{
		final String S_ProcName = "CFSecRamTSecGrpInc.readBuffByIncludeIdx() ";
		ICFSecTSecGrpInc buff;
		ArrayList<ICFSecTSecGrpInc> filteredList = new ArrayList<ICFSecTSecGrpInc>();
		ICFSecTSecGrpInc[] buffList = readDerivedByIncludeIdx( Authorization,
			IncludeGroupId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a017" ) ) {
				filteredList.add( (ICFSecTSecGrpInc)buff );
			}
		}
		return( filteredList.toArray( new ICFSecTSecGrpInc[0] ) );
	}

	public ICFSecTSecGrpInc readBuffByUIncludeIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 TenantId,
		CFLibDbKeyHash256 TSecGroupId,
		CFLibDbKeyHash256 IncludeGroupId )
	{
		final String S_ProcName = "CFSecRamTSecGrpInc.readBuffByUIncludeIdx() ";
		ICFSecTSecGrpInc buff = readDerivedByUIncludeIdx( Authorization,
			TenantId,
			TSecGroupId,
			IncludeGroupId );
		if( ( buff != null ) && buff.getClassCode().equals( "a017" ) ) {
			return( (ICFSecTSecGrpInc)buff );
		}
		else {
			return( null );
		}
	}

	/**
	 *	Read a page array of the specific TSecGrpInc buffer instances identified by the duplicate key TenantIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	TenantId	The TSecGrpInc key attribute of the instance generating the id.
	 *
	 *	@return An array of derived buffer instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	public ICFSecTSecGrpInc[] pageBuffByTenantIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 TenantId,
		CFLibDbKeyHash256 priorTSecGrpIncId )
	{
		final String S_ProcName = "pageBuffByTenantIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	/**
	 *	Read a page array of the specific TSecGrpInc buffer instances identified by the duplicate key GroupIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	TSecGroupId	The TSecGrpInc key attribute of the instance generating the id.
	 *
	 *	@return An array of derived buffer instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	public ICFSecTSecGrpInc[] pageBuffByGroupIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 TSecGroupId,
		CFLibDbKeyHash256 priorTSecGrpIncId )
	{
		final String S_ProcName = "pageBuffByGroupIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	/**
	 *	Read a page array of the specific TSecGrpInc buffer instances identified by the duplicate key IncludeIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	IncludeGroupId	The TSecGrpInc key attribute of the instance generating the id.
	 *
	 *	@return An array of derived buffer instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	public ICFSecTSecGrpInc[] pageBuffByIncludeIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 IncludeGroupId,
		CFLibDbKeyHash256 priorTSecGrpIncId )
	{
		final String S_ProcName = "pageBuffByIncludeIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	public void updateTSecGrpInc( ICFSecAuthorization Authorization,
		ICFSecTSecGrpInc Buff )
	{
		CFLibDbKeyHash256 pkey = schema.getFactoryTSecGrpInc().newPKey();
		pkey.setRequiredTSecGrpIncId( Buff.getRequiredTSecGrpIncId() );
		ICFSecTSecGrpInc existing = dictByPKey.get( pkey );
		if( existing == null ) {
			throw new CFLibStaleCacheDetectedException( getClass(),
				"updateTSecGrpInc",
				"Existing record not found",
				"TSecGrpInc",
				pkey );
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() ) {
			throw new CFLibCollisionDetectedException( getClass(),
				"updateTSecGrpInc",
				pkey );
		}
		Buff.setRequiredRevision( Buff.getRequiredRevision() + 1 );
		CFSecBuffTSecGrpIncByTenantIdxKey existingKeyTenantIdx = schema.getFactoryTSecGrpInc().newTenantIdxKey();
		existingKeyTenantIdx.setRequiredTenantId( existing.getRequiredTenantId() );

		CFSecBuffTSecGrpIncByTenantIdxKey newKeyTenantIdx = schema.getFactoryTSecGrpInc().newTenantIdxKey();
		newKeyTenantIdx.setRequiredTenantId( Buff.getRequiredTenantId() );

		CFSecBuffTSecGrpIncByGroupIdxKey existingKeyGroupIdx = schema.getFactoryTSecGrpInc().newGroupIdxKey();
		existingKeyGroupIdx.setRequiredTSecGroupId( existing.getRequiredTSecGroupId() );

		CFSecBuffTSecGrpIncByGroupIdxKey newKeyGroupIdx = schema.getFactoryTSecGrpInc().newGroupIdxKey();
		newKeyGroupIdx.setRequiredTSecGroupId( Buff.getRequiredTSecGroupId() );

		CFSecBuffTSecGrpIncByIncludeIdxKey existingKeyIncludeIdx = schema.getFactoryTSecGrpInc().newIncludeIdxKey();
		existingKeyIncludeIdx.setRequiredIncludeGroupId( existing.getRequiredIncludeGroupId() );

		CFSecBuffTSecGrpIncByIncludeIdxKey newKeyIncludeIdx = schema.getFactoryTSecGrpInc().newIncludeIdxKey();
		newKeyIncludeIdx.setRequiredIncludeGroupId( Buff.getRequiredIncludeGroupId() );

		CFSecBuffTSecGrpIncByUIncludeIdxKey existingKeyUIncludeIdx = schema.getFactoryTSecGrpInc().newUIncludeIdxKey();
		existingKeyUIncludeIdx.setRequiredTenantId( existing.getRequiredTenantId() );
		existingKeyUIncludeIdx.setRequiredTSecGroupId( existing.getRequiredTSecGroupId() );
		existingKeyUIncludeIdx.setRequiredIncludeGroupId( existing.getRequiredIncludeGroupId() );

		CFSecBuffTSecGrpIncByUIncludeIdxKey newKeyUIncludeIdx = schema.getFactoryTSecGrpInc().newUIncludeIdxKey();
		newKeyUIncludeIdx.setRequiredTenantId( Buff.getRequiredTenantId() );
		newKeyUIncludeIdx.setRequiredTSecGroupId( Buff.getRequiredTSecGroupId() );
		newKeyUIncludeIdx.setRequiredIncludeGroupId( Buff.getRequiredIncludeGroupId() );

		// Check unique indexes

		if( ! existingKeyUIncludeIdx.equals( newKeyUIncludeIdx ) ) {
			if( dictByUIncludeIdx.containsKey( newKeyUIncludeIdx ) ) {
				throw new CFLibUniqueIndexViolationException( getClass(),
					"updateTSecGrpInc",
					"TSecGrpIncUIncludeIdx",
					newKeyUIncludeIdx );
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
						"updateTSecGrpInc",
						"Owner",
						"TSecGrpIncTenant",
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
						"updateTSecGrpInc",
						"Container",
						"TSecGrpIncGroup",
						"TSecGroup",
						null );
				}
			}
		}

		// Update is valid

		Map< CFLibDbKeyHash256, CFSecBuffTSecGrpInc > subdict;

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
			subdict = new HashMap< CFLibDbKeyHash256, CFSecBuffTSecGrpInc >();
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
			subdict = new HashMap< CFLibDbKeyHash256, CFSecBuffTSecGrpInc >();
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
			subdict = new HashMap< CFLibDbKeyHash256, CFSecBuffTSecGrpInc >();
			dictByIncludeIdx.put( newKeyIncludeIdx, subdict );
		}
		subdict.put( pkey, Buff );

		dictByUIncludeIdx.remove( existingKeyUIncludeIdx );
		dictByUIncludeIdx.put( newKeyUIncludeIdx, Buff );

	}

	public void deleteTSecGrpInc( ICFSecAuthorization Authorization,
		ICFSecTSecGrpInc Buff )
	{
		final String S_ProcName = "CFSecRamTSecGrpIncTable.deleteTSecGrpInc() ";
		String classCode;
		CFLibDbKeyHash256 pkey = schema.getFactoryTSecGrpInc().newPKey();
		pkey.setRequiredTSecGrpIncId( Buff.getRequiredTSecGrpIncId() );
		ICFSecTSecGrpInc existing = dictByPKey.get( pkey );
		if( existing == null ) {
			return;
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() )
		{
			throw new CFLibCollisionDetectedException( getClass(),
				"deleteTSecGrpInc",
				pkey );
		}
		CFSecBuffTSecGrpIncByTenantIdxKey keyTenantIdx = schema.getFactoryTSecGrpInc().newTenantIdxKey();
		keyTenantIdx.setRequiredTenantId( existing.getRequiredTenantId() );

		CFSecBuffTSecGrpIncByGroupIdxKey keyGroupIdx = schema.getFactoryTSecGrpInc().newGroupIdxKey();
		keyGroupIdx.setRequiredTSecGroupId( existing.getRequiredTSecGroupId() );

		CFSecBuffTSecGrpIncByIncludeIdxKey keyIncludeIdx = schema.getFactoryTSecGrpInc().newIncludeIdxKey();
		keyIncludeIdx.setRequiredIncludeGroupId( existing.getRequiredIncludeGroupId() );

		CFSecBuffTSecGrpIncByUIncludeIdxKey keyUIncludeIdx = schema.getFactoryTSecGrpInc().newUIncludeIdxKey();
		keyUIncludeIdx.setRequiredTenantId( existing.getRequiredTenantId() );
		keyUIncludeIdx.setRequiredTSecGroupId( existing.getRequiredTSecGroupId() );
		keyUIncludeIdx.setRequiredIncludeGroupId( existing.getRequiredIncludeGroupId() );

		// Validate reverse foreign keys

		// Delete is valid
		Map< CFLibDbKeyHash256, CFSecBuffTSecGrpInc > subdict;

		dictByPKey.remove( pkey );

		subdict = dictByTenantIdx.get( keyTenantIdx );
		subdict.remove( pkey );

		subdict = dictByGroupIdx.get( keyGroupIdx );
		subdict.remove( pkey );

		subdict = dictByIncludeIdx.get( keyIncludeIdx );
		subdict.remove( pkey );

		dictByUIncludeIdx.remove( keyUIncludeIdx );

	}
	public void deleteTSecGrpIncByIdIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argTSecGrpIncId )
	{
		CFLibDbKeyHash256 key = schema.getFactoryTSecGrpInc().newPKey();
		key.setRequiredTSecGrpIncId( argTSecGrpIncId );
		deleteTSecGrpIncByIdIdx( Authorization, key );
	}

	public void deleteTSecGrpIncByIdIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argKey )
	{
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		ICFSecTSecGrpInc cur;
		LinkedList<ICFSecTSecGrpInc> matchSet = new LinkedList<ICFSecTSecGrpInc>();
		Iterator<ICFSecTSecGrpInc> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<ICFSecTSecGrpInc> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableTSecGrpInc().readDerivedByIdIdx( Authorization,
				cur.getRequiredTSecGrpIncId() );
			deleteTSecGrpInc( Authorization, cur );
		}
	}

	public void deleteTSecGrpIncByTenantIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argTenantId )
	{
		CFSecBuffTSecGrpIncByTenantIdxKey key = schema.getFactoryTSecGrpInc().newTenantIdxKey();
		key.setRequiredTenantId( argTenantId );
		deleteTSecGrpIncByTenantIdx( Authorization, key );
	}

	public void deleteTSecGrpIncByTenantIdx( ICFSecAuthorization Authorization,
		ICFSecTSecGrpIncByTenantIdxKey argKey )
	{
		ICFSecTSecGrpInc cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<ICFSecTSecGrpInc> matchSet = new LinkedList<ICFSecTSecGrpInc>();
		Iterator<ICFSecTSecGrpInc> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<ICFSecTSecGrpInc> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableTSecGrpInc().readDerivedByIdIdx( Authorization,
				cur.getRequiredTSecGrpIncId() );
			deleteTSecGrpInc( Authorization, cur );
		}
	}

	public void deleteTSecGrpIncByGroupIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argTSecGroupId )
	{
		CFSecBuffTSecGrpIncByGroupIdxKey key = schema.getFactoryTSecGrpInc().newGroupIdxKey();
		key.setRequiredTSecGroupId( argTSecGroupId );
		deleteTSecGrpIncByGroupIdx( Authorization, key );
	}

	public void deleteTSecGrpIncByGroupIdx( ICFSecAuthorization Authorization,
		ICFSecTSecGrpIncByGroupIdxKey argKey )
	{
		ICFSecTSecGrpInc cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<ICFSecTSecGrpInc> matchSet = new LinkedList<ICFSecTSecGrpInc>();
		Iterator<ICFSecTSecGrpInc> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<ICFSecTSecGrpInc> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableTSecGrpInc().readDerivedByIdIdx( Authorization,
				cur.getRequiredTSecGrpIncId() );
			deleteTSecGrpInc( Authorization, cur );
		}
	}

	public void deleteTSecGrpIncByIncludeIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argIncludeGroupId )
	{
		CFSecBuffTSecGrpIncByIncludeIdxKey key = schema.getFactoryTSecGrpInc().newIncludeIdxKey();
		key.setRequiredIncludeGroupId( argIncludeGroupId );
		deleteTSecGrpIncByIncludeIdx( Authorization, key );
	}

	public void deleteTSecGrpIncByIncludeIdx( ICFSecAuthorization Authorization,
		ICFSecTSecGrpIncByIncludeIdxKey argKey )
	{
		ICFSecTSecGrpInc cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<ICFSecTSecGrpInc> matchSet = new LinkedList<ICFSecTSecGrpInc>();
		Iterator<ICFSecTSecGrpInc> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<ICFSecTSecGrpInc> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableTSecGrpInc().readDerivedByIdIdx( Authorization,
				cur.getRequiredTSecGrpIncId() );
			deleteTSecGrpInc( Authorization, cur );
		}
	}

	public void deleteTSecGrpIncByUIncludeIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argTenantId,
		CFLibDbKeyHash256 argTSecGroupId,
		CFLibDbKeyHash256 argIncludeGroupId )
	{
		CFSecBuffTSecGrpIncByUIncludeIdxKey key = schema.getFactoryTSecGrpInc().newUIncludeIdxKey();
		key.setRequiredTenantId( argTenantId );
		key.setRequiredTSecGroupId( argTSecGroupId );
		key.setRequiredIncludeGroupId( argIncludeGroupId );
		deleteTSecGrpIncByUIncludeIdx( Authorization, key );
	}

	public void deleteTSecGrpIncByUIncludeIdx( ICFSecAuthorization Authorization,
		ICFSecTSecGrpIncByUIncludeIdxKey argKey )
	{
		ICFSecTSecGrpInc cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<ICFSecTSecGrpInc> matchSet = new LinkedList<ICFSecTSecGrpInc>();
		Iterator<ICFSecTSecGrpInc> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<ICFSecTSecGrpInc> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableTSecGrpInc().readDerivedByIdIdx( Authorization,
				cur.getRequiredTSecGrpIncId() );
			deleteTSecGrpInc( Authorization, cur );
		}
	}
}
