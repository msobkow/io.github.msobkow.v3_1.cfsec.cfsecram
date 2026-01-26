
// Description: Java 25 in-memory RAM DbIO implementation for TSecGroup.

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
 *	CFSecRamTSecGroupTable in-memory RAM DbIO implementation
 *	for TSecGroup.
 */
public class CFSecRamTSecGroupTable
	implements ICFSecTSecGroupTable
{
	private ICFSecSchema schema;
	private Map< CFLibDbKeyHash256,
				CFSecBuffTSecGroup > dictByPKey
		= new HashMap< CFLibDbKeyHash256,
				CFSecBuffTSecGroup >();
	private Map< CFSecBuffTSecGroupByTenantIdxKey,
				Map< CFLibDbKeyHash256,
					CFSecBuffTSecGroup >> dictByTenantIdx
		= new HashMap< CFSecBuffTSecGroupByTenantIdxKey,
				Map< CFLibDbKeyHash256,
					CFSecBuffTSecGroup >>();
	private Map< CFSecBuffTSecGroupByTenantVisIdxKey,
				Map< CFLibDbKeyHash256,
					CFSecBuffTSecGroup >> dictByTenantVisIdx
		= new HashMap< CFSecBuffTSecGroupByTenantVisIdxKey,
				Map< CFLibDbKeyHash256,
					CFSecBuffTSecGroup >>();
	private Map< CFSecBuffTSecGroupByUNameIdxKey,
			CFSecBuffTSecGroup > dictByUNameIdx
		= new HashMap< CFSecBuffTSecGroupByUNameIdxKey,
			CFSecBuffTSecGroup >();

	public CFSecRamTSecGroupTable( ICFSecSchema argSchema ) {
		schema = argSchema;
	}

	public void createTSecGroup( ICFSecAuthorization Authorization,
		ICFSecTSecGroup Buff )
	{
		final String S_ProcName = "createTSecGroup";
		CFLibDbKeyHash256 pkey = schema.getFactoryTSecGroup().newPKey();
		pkey.setRequiredTSecGroupId( schema.nextTSecGroupIdGen() );
		Buff.setRequiredTSecGroupId( pkey.getRequiredTSecGroupId() );
		CFSecBuffTSecGroupByTenantIdxKey keyTenantIdx = schema.getFactoryTSecGroup().newTenantIdxKey();
		keyTenantIdx.setRequiredTenantId( Buff.getRequiredTenantId() );

		CFSecBuffTSecGroupByTenantVisIdxKey keyTenantVisIdx = schema.getFactoryTSecGroup().newTenantVisIdxKey();
		keyTenantVisIdx.setRequiredTenantId( Buff.getRequiredTenantId() );
		keyTenantVisIdx.setRequiredIsVisible( Buff.getRequiredIsVisible() );

		CFSecBuffTSecGroupByUNameIdxKey keyUNameIdx = schema.getFactoryTSecGroup().newUNameIdxKey();
		keyUNameIdx.setRequiredTenantId( Buff.getRequiredTenantId() );
		keyUNameIdx.setRequiredName( Buff.getRequiredName() );

		// Validate unique indexes

		if( dictByPKey.containsKey( pkey ) ) {
			throw new CFLibPrimaryKeyNotNewException( getClass(), S_ProcName, pkey );
		}

		if( dictByUNameIdx.containsKey( keyUNameIdx ) ) {
			throw new CFLibUniqueIndexViolationException( getClass(),
				S_ProcName,
				"TSecGroupUNameIdx",
				keyUNameIdx );
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
						"Container",
						"TSecGroupTenant",
						"Tenant",
						null );
				}
			}
		}

		// Proceed with adding the new record

		dictByPKey.put( pkey, Buff );

		Map< CFLibDbKeyHash256, CFSecBuffTSecGroup > subdictTenantIdx;
		if( dictByTenantIdx.containsKey( keyTenantIdx ) ) {
			subdictTenantIdx = dictByTenantIdx.get( keyTenantIdx );
		}
		else {
			subdictTenantIdx = new HashMap< CFLibDbKeyHash256, CFSecBuffTSecGroup >();
			dictByTenantIdx.put( keyTenantIdx, subdictTenantIdx );
		}
		subdictTenantIdx.put( pkey, Buff );

		Map< CFLibDbKeyHash256, CFSecBuffTSecGroup > subdictTenantVisIdx;
		if( dictByTenantVisIdx.containsKey( keyTenantVisIdx ) ) {
			subdictTenantVisIdx = dictByTenantVisIdx.get( keyTenantVisIdx );
		}
		else {
			subdictTenantVisIdx = new HashMap< CFLibDbKeyHash256, CFSecBuffTSecGroup >();
			dictByTenantVisIdx.put( keyTenantVisIdx, subdictTenantVisIdx );
		}
		subdictTenantVisIdx.put( pkey, Buff );

		dictByUNameIdx.put( keyUNameIdx, Buff );

	}

	public ICFSecTSecGroup readDerived( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 PKey )
	{
		final String S_ProcName = "CFSecRamTSecGroup.readDerived";
		ICFSecTSecGroup buff;
		if( dictByPKey.containsKey( PKey ) ) {
			buff = dictByPKey.get( PKey );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public ICFSecTSecGroup lockDerived( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 PKey )
	{
		final String S_ProcName = "CFSecRamTSecGroup.readDerived";
		CFLibDbKeyHash256 key = schema.getFactoryTSecGroup().newPKey();
		key.setRequiredTSecGroupId( PKey.getRequiredTSecGroupId() );
		ICFSecTSecGroup buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public ICFSecTSecGroup[] readAllDerived( ICFSecAuthorization Authorization ) {
		final String S_ProcName = "CFSecRamTSecGroup.readAllDerived";
		ICFSecTSecGroup[] retList = new ICFSecTSecGroup[ dictByPKey.values().size() ];
		Iterator< ICFSecTSecGroup > iter = dictByPKey.values().iterator();
		int idx = 0;
		while( iter.hasNext() ) {
			retList[ idx++ ] = iter.next();
		}
		return( retList );
	}

	public ICFSecTSecGroup[] readDerivedByTenantIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 TenantId )
	{
		final String S_ProcName = "CFSecRamTSecGroup.readDerivedByTenantIdx";
		CFSecBuffTSecGroupByTenantIdxKey key = schema.getFactoryTSecGroup().newTenantIdxKey();
		key.setRequiredTenantId( TenantId );

		ICFSecTSecGroup[] recArray;
		if( dictByTenantIdx.containsKey( key ) ) {
			Map< CFLibDbKeyHash256, CFSecBuffTSecGroup > subdictTenantIdx
				= dictByTenantIdx.get( key );
			recArray = new ICFSecTSecGroup[ subdictTenantIdx.size() ];
			Iterator< ICFSecTSecGroup > iter = subdictTenantIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFLibDbKeyHash256, CFSecBuffTSecGroup > subdictTenantIdx
				= new HashMap< CFLibDbKeyHash256, CFSecBuffTSecGroup >();
			dictByTenantIdx.put( key, subdictTenantIdx );
			recArray = new ICFSecTSecGroup[0];
		}
		return( recArray );
	}

	public ICFSecTSecGroup[] readDerivedByTenantVisIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 TenantId,
		boolean IsVisible )
	{
		final String S_ProcName = "CFSecRamTSecGroup.readDerivedByTenantVisIdx";
		CFSecBuffTSecGroupByTenantVisIdxKey key = schema.getFactoryTSecGroup().newTenantVisIdxKey();
		key.setRequiredTenantId( TenantId );
		key.setRequiredIsVisible( IsVisible );

		ICFSecTSecGroup[] recArray;
		if( dictByTenantVisIdx.containsKey( key ) ) {
			Map< CFLibDbKeyHash256, CFSecBuffTSecGroup > subdictTenantVisIdx
				= dictByTenantVisIdx.get( key );
			recArray = new ICFSecTSecGroup[ subdictTenantVisIdx.size() ];
			Iterator< ICFSecTSecGroup > iter = subdictTenantVisIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFLibDbKeyHash256, CFSecBuffTSecGroup > subdictTenantVisIdx
				= new HashMap< CFLibDbKeyHash256, CFSecBuffTSecGroup >();
			dictByTenantVisIdx.put( key, subdictTenantVisIdx );
			recArray = new ICFSecTSecGroup[0];
		}
		return( recArray );
	}

	public ICFSecTSecGroup readDerivedByUNameIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 TenantId,
		String Name )
	{
		final String S_ProcName = "CFSecRamTSecGroup.readDerivedByUNameIdx";
		CFSecBuffTSecGroupByUNameIdxKey key = schema.getFactoryTSecGroup().newUNameIdxKey();
		key.setRequiredTenantId( TenantId );
		key.setRequiredName( Name );

		ICFSecTSecGroup buff;
		if( dictByUNameIdx.containsKey( key ) ) {
			buff = dictByUNameIdx.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public ICFSecTSecGroup readDerivedByIdIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 TSecGroupId )
	{
		final String S_ProcName = "CFSecRamTSecGroup.readDerivedByIdIdx() ";
		CFLibDbKeyHash256 key = schema.getFactoryTSecGroup().newPKey();
		key.setRequiredTSecGroupId( TSecGroupId );

		ICFSecTSecGroup buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public ICFSecTSecGroup readBuff( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 PKey )
	{
		final String S_ProcName = "CFSecRamTSecGroup.readBuff";
		ICFSecTSecGroup buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( ! buff.getClassCode().equals( "a016" ) ) ) {
			buff = null;
		}
		return( buff );
	}

	public ICFSecTSecGroup lockBuff( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 PKey )
	{
		final String S_ProcName = "lockBuff";
		ICFSecTSecGroup buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( ! buff.getClassCode().equals( "a016" ) ) ) {
			buff = null;
		}
		return( buff );
	}

	public ICFSecTSecGroup[] readAllBuff( ICFSecAuthorization Authorization )
	{
		final String S_ProcName = "CFSecRamTSecGroup.readAllBuff";
		ICFSecTSecGroup buff;
		ArrayList<ICFSecTSecGroup> filteredList = new ArrayList<ICFSecTSecGroup>();
		ICFSecTSecGroup[] buffList = readAllDerived( Authorization );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a016" ) ) {
				filteredList.add( buff );
			}
		}
		return( filteredList.toArray( new ICFSecTSecGroup[0] ) );
	}

	public ICFSecTSecGroup readBuffByIdIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 TSecGroupId )
	{
		final String S_ProcName = "CFSecRamTSecGroup.readBuffByIdIdx() ";
		ICFSecTSecGroup buff = readDerivedByIdIdx( Authorization,
			TSecGroupId );
		if( ( buff != null ) && buff.getClassCode().equals( "a016" ) ) {
			return( (ICFSecTSecGroup)buff );
		}
		else {
			return( null );
		}
	}

	public ICFSecTSecGroup[] readBuffByTenantIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 TenantId )
	{
		final String S_ProcName = "CFSecRamTSecGroup.readBuffByTenantIdx() ";
		ICFSecTSecGroup buff;
		ArrayList<ICFSecTSecGroup> filteredList = new ArrayList<ICFSecTSecGroup>();
		ICFSecTSecGroup[] buffList = readDerivedByTenantIdx( Authorization,
			TenantId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a016" ) ) {
				filteredList.add( (ICFSecTSecGroup)buff );
			}
		}
		return( filteredList.toArray( new ICFSecTSecGroup[0] ) );
	}

	public ICFSecTSecGroup[] readBuffByTenantVisIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 TenantId,
		boolean IsVisible )
	{
		final String S_ProcName = "CFSecRamTSecGroup.readBuffByTenantVisIdx() ";
		ICFSecTSecGroup buff;
		ArrayList<ICFSecTSecGroup> filteredList = new ArrayList<ICFSecTSecGroup>();
		ICFSecTSecGroup[] buffList = readDerivedByTenantVisIdx( Authorization,
			TenantId,
			IsVisible );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a016" ) ) {
				filteredList.add( (ICFSecTSecGroup)buff );
			}
		}
		return( filteredList.toArray( new ICFSecTSecGroup[0] ) );
	}

	public ICFSecTSecGroup readBuffByUNameIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 TenantId,
		String Name )
	{
		final String S_ProcName = "CFSecRamTSecGroup.readBuffByUNameIdx() ";
		ICFSecTSecGroup buff = readDerivedByUNameIdx( Authorization,
			TenantId,
			Name );
		if( ( buff != null ) && buff.getClassCode().equals( "a016" ) ) {
			return( (ICFSecTSecGroup)buff );
		}
		else {
			return( null );
		}
	}

	public void updateTSecGroup( ICFSecAuthorization Authorization,
		ICFSecTSecGroup Buff )
	{
		CFLibDbKeyHash256 pkey = schema.getFactoryTSecGroup().newPKey();
		pkey.setRequiredTSecGroupId( Buff.getRequiredTSecGroupId() );
		ICFSecTSecGroup existing = dictByPKey.get( pkey );
		if( existing == null ) {
			throw new CFLibStaleCacheDetectedException( getClass(),
				"updateTSecGroup",
				"Existing record not found",
				"TSecGroup",
				pkey );
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() ) {
			throw new CFLibCollisionDetectedException( getClass(),
				"updateTSecGroup",
				pkey );
		}
		Buff.setRequiredRevision( Buff.getRequiredRevision() + 1 );
		CFSecBuffTSecGroupByTenantIdxKey existingKeyTenantIdx = schema.getFactoryTSecGroup().newTenantIdxKey();
		existingKeyTenantIdx.setRequiredTenantId( existing.getRequiredTenantId() );

		CFSecBuffTSecGroupByTenantIdxKey newKeyTenantIdx = schema.getFactoryTSecGroup().newTenantIdxKey();
		newKeyTenantIdx.setRequiredTenantId( Buff.getRequiredTenantId() );

		CFSecBuffTSecGroupByTenantVisIdxKey existingKeyTenantVisIdx = schema.getFactoryTSecGroup().newTenantVisIdxKey();
		existingKeyTenantVisIdx.setRequiredTenantId( existing.getRequiredTenantId() );
		existingKeyTenantVisIdx.setRequiredIsVisible( existing.getRequiredIsVisible() );

		CFSecBuffTSecGroupByTenantVisIdxKey newKeyTenantVisIdx = schema.getFactoryTSecGroup().newTenantVisIdxKey();
		newKeyTenantVisIdx.setRequiredTenantId( Buff.getRequiredTenantId() );
		newKeyTenantVisIdx.setRequiredIsVisible( Buff.getRequiredIsVisible() );

		CFSecBuffTSecGroupByUNameIdxKey existingKeyUNameIdx = schema.getFactoryTSecGroup().newUNameIdxKey();
		existingKeyUNameIdx.setRequiredTenantId( existing.getRequiredTenantId() );
		existingKeyUNameIdx.setRequiredName( existing.getRequiredName() );

		CFSecBuffTSecGroupByUNameIdxKey newKeyUNameIdx = schema.getFactoryTSecGroup().newUNameIdxKey();
		newKeyUNameIdx.setRequiredTenantId( Buff.getRequiredTenantId() );
		newKeyUNameIdx.setRequiredName( Buff.getRequiredName() );

		// Check unique indexes

		if( ! existingKeyUNameIdx.equals( newKeyUNameIdx ) ) {
			if( dictByUNameIdx.containsKey( newKeyUNameIdx ) ) {
				throw new CFLibUniqueIndexViolationException( getClass(),
					"updateTSecGroup",
					"TSecGroupUNameIdx",
					newKeyUNameIdx );
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
						"updateTSecGroup",
						"Container",
						"TSecGroupTenant",
						"Tenant",
						null );
				}
			}
		}

		// Update is valid

		Map< CFLibDbKeyHash256, CFSecBuffTSecGroup > subdict;

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
			subdict = new HashMap< CFLibDbKeyHash256, CFSecBuffTSecGroup >();
			dictByTenantIdx.put( newKeyTenantIdx, subdict );
		}
		subdict.put( pkey, Buff );

		subdict = dictByTenantVisIdx.get( existingKeyTenantVisIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictByTenantVisIdx.containsKey( newKeyTenantVisIdx ) ) {
			subdict = dictByTenantVisIdx.get( newKeyTenantVisIdx );
		}
		else {
			subdict = new HashMap< CFLibDbKeyHash256, CFSecBuffTSecGroup >();
			dictByTenantVisIdx.put( newKeyTenantVisIdx, subdict );
		}
		subdict.put( pkey, Buff );

		dictByUNameIdx.remove( existingKeyUNameIdx );
		dictByUNameIdx.put( newKeyUNameIdx, Buff );

	}

	public void deleteTSecGroup( ICFSecAuthorization Authorization,
		ICFSecTSecGroup Buff )
	{
		final String S_ProcName = "CFSecRamTSecGroupTable.deleteTSecGroup() ";
		String classCode;
		CFLibDbKeyHash256 pkey = schema.getFactoryTSecGroup().newPKey();
		pkey.setRequiredTSecGroupId( Buff.getRequiredTSecGroupId() );
		ICFSecTSecGroup existing = dictByPKey.get( pkey );
		if( existing == null ) {
			return;
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() )
		{
			throw new CFLibCollisionDetectedException( getClass(),
				"deleteTSecGroup",
				pkey );
		}
					schema.getTableTSecGrpInc().deleteTSecGrpIncByIncludeIdx( Authorization,
						existing.getRequiredTSecGroupId() );
					schema.getTableTSecGrpMemb().deleteTSecGrpMembByGroupIdx( Authorization,
						existing.getRequiredTSecGroupId() );
					schema.getTableTSecGrpInc().deleteTSecGrpIncByGroupIdx( Authorization,
						existing.getRequiredTSecGroupId() );
		CFSecBuffTSecGroupByTenantIdxKey keyTenantIdx = schema.getFactoryTSecGroup().newTenantIdxKey();
		keyTenantIdx.setRequiredTenantId( existing.getRequiredTenantId() );

		CFSecBuffTSecGroupByTenantVisIdxKey keyTenantVisIdx = schema.getFactoryTSecGroup().newTenantVisIdxKey();
		keyTenantVisIdx.setRequiredTenantId( existing.getRequiredTenantId() );
		keyTenantVisIdx.setRequiredIsVisible( existing.getRequiredIsVisible() );

		CFSecBuffTSecGroupByUNameIdxKey keyUNameIdx = schema.getFactoryTSecGroup().newUNameIdxKey();
		keyUNameIdx.setRequiredTenantId( existing.getRequiredTenantId() );
		keyUNameIdx.setRequiredName( existing.getRequiredName() );

		// Validate reverse foreign keys

		// Delete is valid
		Map< CFLibDbKeyHash256, CFSecBuffTSecGroup > subdict;

		dictByPKey.remove( pkey );

		subdict = dictByTenantIdx.get( keyTenantIdx );
		subdict.remove( pkey );

		subdict = dictByTenantVisIdx.get( keyTenantVisIdx );
		subdict.remove( pkey );

		dictByUNameIdx.remove( keyUNameIdx );

	}
	public void deleteTSecGroupByIdIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argTSecGroupId )
	{
		CFLibDbKeyHash256 key = schema.getFactoryTSecGroup().newPKey();
		key.setRequiredTSecGroupId( argTSecGroupId );
		deleteTSecGroupByIdIdx( Authorization, key );
	}

	public void deleteTSecGroupByIdIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argKey )
	{
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		ICFSecTSecGroup cur;
		LinkedList<ICFSecTSecGroup> matchSet = new LinkedList<ICFSecTSecGroup>();
		Iterator<ICFSecTSecGroup> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<ICFSecTSecGroup> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableTSecGroup().readDerivedByIdIdx( Authorization,
				cur.getRequiredTSecGroupId() );
			deleteTSecGroup( Authorization, cur );
		}
	}

	public void deleteTSecGroupByTenantIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argTenantId )
	{
		CFSecBuffTSecGroupByTenantIdxKey key = schema.getFactoryTSecGroup().newTenantIdxKey();
		key.setRequiredTenantId( argTenantId );
		deleteTSecGroupByTenantIdx( Authorization, key );
	}

	public void deleteTSecGroupByTenantIdx( ICFSecAuthorization Authorization,
		ICFSecTSecGroupByTenantIdxKey argKey )
	{
		ICFSecTSecGroup cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<ICFSecTSecGroup> matchSet = new LinkedList<ICFSecTSecGroup>();
		Iterator<ICFSecTSecGroup> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<ICFSecTSecGroup> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableTSecGroup().readDerivedByIdIdx( Authorization,
				cur.getRequiredTSecGroupId() );
			deleteTSecGroup( Authorization, cur );
		}
	}

	public void deleteTSecGroupByTenantVisIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argTenantId,
		boolean argIsVisible )
	{
		CFSecBuffTSecGroupByTenantVisIdxKey key = schema.getFactoryTSecGroup().newTenantVisIdxKey();
		key.setRequiredTenantId( argTenantId );
		key.setRequiredIsVisible( argIsVisible );
		deleteTSecGroupByTenantVisIdx( Authorization, key );
	}

	public void deleteTSecGroupByTenantVisIdx( ICFSecAuthorization Authorization,
		ICFSecTSecGroupByTenantVisIdxKey argKey )
	{
		ICFSecTSecGroup cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<ICFSecTSecGroup> matchSet = new LinkedList<ICFSecTSecGroup>();
		Iterator<ICFSecTSecGroup> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<ICFSecTSecGroup> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableTSecGroup().readDerivedByIdIdx( Authorization,
				cur.getRequiredTSecGroupId() );
			deleteTSecGroup( Authorization, cur );
		}
	}

	public void deleteTSecGroupByUNameIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argTenantId,
		String argName )
	{
		CFSecBuffTSecGroupByUNameIdxKey key = schema.getFactoryTSecGroup().newUNameIdxKey();
		key.setRequiredTenantId( argTenantId );
		key.setRequiredName( argName );
		deleteTSecGroupByUNameIdx( Authorization, key );
	}

	public void deleteTSecGroupByUNameIdx( ICFSecAuthorization Authorization,
		ICFSecTSecGroupByUNameIdxKey argKey )
	{
		ICFSecTSecGroup cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<ICFSecTSecGroup> matchSet = new LinkedList<ICFSecTSecGroup>();
		Iterator<ICFSecTSecGroup> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<ICFSecTSecGroup> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableTSecGroup().readDerivedByIdIdx( Authorization,
				cur.getRequiredTSecGroupId() );
			deleteTSecGroup( Authorization, cur );
		}
	}
}
