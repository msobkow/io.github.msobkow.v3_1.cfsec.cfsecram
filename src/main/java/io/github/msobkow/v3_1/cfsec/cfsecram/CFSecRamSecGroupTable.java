
// Description: Java 25 in-memory RAM DbIO implementation for SecGroup.

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
 *	CFSecRamSecGroupTable in-memory RAM DbIO implementation
 *	for SecGroup.
 */
public class CFSecRamSecGroupTable
	implements ICFSecSecGroupTable
{
	private ICFSecSchema schema;
	private Map< CFLibDbKeyHash256,
				CFSecBuffSecGroup > dictByPKey
		= new HashMap< CFLibDbKeyHash256,
				CFSecBuffSecGroup >();
	private Map< CFSecBuffSecGroupByClusterIdxKey,
				Map< CFLibDbKeyHash256,
					CFSecBuffSecGroup >> dictByClusterIdx
		= new HashMap< CFSecBuffSecGroupByClusterIdxKey,
				Map< CFLibDbKeyHash256,
					CFSecBuffSecGroup >>();
	private Map< CFSecBuffSecGroupByClusterVisIdxKey,
				Map< CFLibDbKeyHash256,
					CFSecBuffSecGroup >> dictByClusterVisIdx
		= new HashMap< CFSecBuffSecGroupByClusterVisIdxKey,
				Map< CFLibDbKeyHash256,
					CFSecBuffSecGroup >>();
	private Map< CFSecBuffSecGroupByUNameIdxKey,
			CFSecBuffSecGroup > dictByUNameIdx
		= new HashMap< CFSecBuffSecGroupByUNameIdxKey,
			CFSecBuffSecGroup >();

	public CFSecRamSecGroupTable( ICFSecSchema argSchema ) {
		schema = argSchema;
	}

	public void createSecGroup( ICFSecAuthorization Authorization,
		ICFSecSecGroup Buff )
	{
		final String S_ProcName = "createSecGroup";
		CFLibDbKeyHash256 pkey = schema.getFactorySecGroup().newPKey();
		pkey.setRequiredSecGroupId( schema.nextSecGroupIdGen() );
		Buff.setRequiredSecGroupId( pkey.getRequiredSecGroupId() );
		CFSecBuffSecGroupByClusterIdxKey keyClusterIdx = schema.getFactorySecGroup().newClusterIdxKey();
		keyClusterIdx.setRequiredClusterId( Buff.getRequiredClusterId() );

		CFSecBuffSecGroupByClusterVisIdxKey keyClusterVisIdx = schema.getFactorySecGroup().newClusterVisIdxKey();
		keyClusterVisIdx.setRequiredClusterId( Buff.getRequiredClusterId() );
		keyClusterVisIdx.setRequiredIsVisible( Buff.getRequiredIsVisible() );

		CFSecBuffSecGroupByUNameIdxKey keyUNameIdx = schema.getFactorySecGroup().newUNameIdxKey();
		keyUNameIdx.setRequiredClusterId( Buff.getRequiredClusterId() );
		keyUNameIdx.setRequiredName( Buff.getRequiredName() );

		// Validate unique indexes

		if( dictByPKey.containsKey( pkey ) ) {
			throw new CFLibPrimaryKeyNotNewException( getClass(), S_ProcName, pkey );
		}

		if( dictByUNameIdx.containsKey( keyUNameIdx ) ) {
			throw new CFLibUniqueIndexViolationException( getClass(),
				S_ProcName,
				"SecGroupUNameIdx",
				keyUNameIdx );
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
						"Container",
						"SecGroupCluster",
						"Cluster",
						null );
				}
			}
		}

		// Proceed with adding the new record

		dictByPKey.put( pkey, Buff );

		Map< CFLibDbKeyHash256, CFSecBuffSecGroup > subdictClusterIdx;
		if( dictByClusterIdx.containsKey( keyClusterIdx ) ) {
			subdictClusterIdx = dictByClusterIdx.get( keyClusterIdx );
		}
		else {
			subdictClusterIdx = new HashMap< CFLibDbKeyHash256, CFSecBuffSecGroup >();
			dictByClusterIdx.put( keyClusterIdx, subdictClusterIdx );
		}
		subdictClusterIdx.put( pkey, Buff );

		Map< CFLibDbKeyHash256, CFSecBuffSecGroup > subdictClusterVisIdx;
		if( dictByClusterVisIdx.containsKey( keyClusterVisIdx ) ) {
			subdictClusterVisIdx = dictByClusterVisIdx.get( keyClusterVisIdx );
		}
		else {
			subdictClusterVisIdx = new HashMap< CFLibDbKeyHash256, CFSecBuffSecGroup >();
			dictByClusterVisIdx.put( keyClusterVisIdx, subdictClusterVisIdx );
		}
		subdictClusterVisIdx.put( pkey, Buff );

		dictByUNameIdx.put( keyUNameIdx, Buff );

	}

	public ICFSecSecGroup readDerived( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 PKey )
	{
		final String S_ProcName = "CFSecRamSecGroup.readDerived";
		ICFSecSecGroup buff;
		if( dictByPKey.containsKey( PKey ) ) {
			buff = dictByPKey.get( PKey );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public ICFSecSecGroup lockDerived( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 PKey )
	{
		final String S_ProcName = "CFSecRamSecGroup.readDerived";
		CFLibDbKeyHash256 key = schema.getFactorySecGroup().newPKey();
		key.setRequiredSecGroupId( PKey.getRequiredSecGroupId() );
		ICFSecSecGroup buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public ICFSecSecGroup[] readAllDerived( ICFSecAuthorization Authorization ) {
		final String S_ProcName = "CFSecRamSecGroup.readAllDerived";
		ICFSecSecGroup[] retList = new ICFSecSecGroup[ dictByPKey.values().size() ];
		Iterator< ICFSecSecGroup > iter = dictByPKey.values().iterator();
		int idx = 0;
		while( iter.hasNext() ) {
			retList[ idx++ ] = iter.next();
		}
		return( retList );
	}

	public ICFSecSecGroup[] readDerivedByClusterIdx( ICFSecAuthorization Authorization,
		long ClusterId )
	{
		final String S_ProcName = "CFSecRamSecGroup.readDerivedByClusterIdx";
		CFSecBuffSecGroupByClusterIdxKey key = schema.getFactorySecGroup().newClusterIdxKey();
		key.setRequiredClusterId( ClusterId );

		ICFSecSecGroup[] recArray;
		if( dictByClusterIdx.containsKey( key ) ) {
			Map< CFLibDbKeyHash256, CFSecBuffSecGroup > subdictClusterIdx
				= dictByClusterIdx.get( key );
			recArray = new ICFSecSecGroup[ subdictClusterIdx.size() ];
			Iterator< ICFSecSecGroup > iter = subdictClusterIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFLibDbKeyHash256, CFSecBuffSecGroup > subdictClusterIdx
				= new HashMap< CFLibDbKeyHash256, CFSecBuffSecGroup >();
			dictByClusterIdx.put( key, subdictClusterIdx );
			recArray = new ICFSecSecGroup[0];
		}
		return( recArray );
	}

	public ICFSecSecGroup[] readDerivedByClusterVisIdx( ICFSecAuthorization Authorization,
		long ClusterId,
		boolean IsVisible )
	{
		final String S_ProcName = "CFSecRamSecGroup.readDerivedByClusterVisIdx";
		CFSecBuffSecGroupByClusterVisIdxKey key = schema.getFactorySecGroup().newClusterVisIdxKey();
		key.setRequiredClusterId( ClusterId );
		key.setRequiredIsVisible( IsVisible );

		ICFSecSecGroup[] recArray;
		if( dictByClusterVisIdx.containsKey( key ) ) {
			Map< CFLibDbKeyHash256, CFSecBuffSecGroup > subdictClusterVisIdx
				= dictByClusterVisIdx.get( key );
			recArray = new ICFSecSecGroup[ subdictClusterVisIdx.size() ];
			Iterator< ICFSecSecGroup > iter = subdictClusterVisIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFLibDbKeyHash256, CFSecBuffSecGroup > subdictClusterVisIdx
				= new HashMap< CFLibDbKeyHash256, CFSecBuffSecGroup >();
			dictByClusterVisIdx.put( key, subdictClusterVisIdx );
			recArray = new ICFSecSecGroup[0];
		}
		return( recArray );
	}

	public ICFSecSecGroup readDerivedByUNameIdx( ICFSecAuthorization Authorization,
		long ClusterId,
		String Name )
	{
		final String S_ProcName = "CFSecRamSecGroup.readDerivedByUNameIdx";
		CFSecBuffSecGroupByUNameIdxKey key = schema.getFactorySecGroup().newUNameIdxKey();
		key.setRequiredClusterId( ClusterId );
		key.setRequiredName( Name );

		ICFSecSecGroup buff;
		if( dictByUNameIdx.containsKey( key ) ) {
			buff = dictByUNameIdx.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public ICFSecSecGroup readDerivedByIdIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecGroupId )
	{
		final String S_ProcName = "CFSecRamSecGroup.readDerivedByIdIdx() ";
		CFLibDbKeyHash256 key = schema.getFactorySecGroup().newPKey();
		key.setRequiredSecGroupId( SecGroupId );

		ICFSecSecGroup buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public ICFSecSecGroup readBuff( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 PKey )
	{
		final String S_ProcName = "CFSecRamSecGroup.readBuff";
		ICFSecSecGroup buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( ! buff.getClassCode().equals( "a00c" ) ) ) {
			buff = null;
		}
		return( buff );
	}

	public ICFSecSecGroup lockBuff( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 PKey )
	{
		final String S_ProcName = "lockBuff";
		ICFSecSecGroup buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( ! buff.getClassCode().equals( "a00c" ) ) ) {
			buff = null;
		}
		return( buff );
	}

	public ICFSecSecGroup[] readAllBuff( ICFSecAuthorization Authorization )
	{
		final String S_ProcName = "CFSecRamSecGroup.readAllBuff";
		ICFSecSecGroup buff;
		ArrayList<ICFSecSecGroup> filteredList = new ArrayList<ICFSecSecGroup>();
		ICFSecSecGroup[] buffList = readAllDerived( Authorization );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a00c" ) ) {
				filteredList.add( buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecGroup[0] ) );
	}

	public ICFSecSecGroup readBuffByIdIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecGroupId )
	{
		final String S_ProcName = "CFSecRamSecGroup.readBuffByIdIdx() ";
		ICFSecSecGroup buff = readDerivedByIdIdx( Authorization,
			SecGroupId );
		if( ( buff != null ) && buff.getClassCode().equals( "a00c" ) ) {
			return( (ICFSecSecGroup)buff );
		}
		else {
			return( null );
		}
	}

	public ICFSecSecGroup[] readBuffByClusterIdx( ICFSecAuthorization Authorization,
		long ClusterId )
	{
		final String S_ProcName = "CFSecRamSecGroup.readBuffByClusterIdx() ";
		ICFSecSecGroup buff;
		ArrayList<ICFSecSecGroup> filteredList = new ArrayList<ICFSecSecGroup>();
		ICFSecSecGroup[] buffList = readDerivedByClusterIdx( Authorization,
			ClusterId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a00c" ) ) {
				filteredList.add( (ICFSecSecGroup)buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecGroup[0] ) );
	}

	public ICFSecSecGroup[] readBuffByClusterVisIdx( ICFSecAuthorization Authorization,
		long ClusterId,
		boolean IsVisible )
	{
		final String S_ProcName = "CFSecRamSecGroup.readBuffByClusterVisIdx() ";
		ICFSecSecGroup buff;
		ArrayList<ICFSecSecGroup> filteredList = new ArrayList<ICFSecSecGroup>();
		ICFSecSecGroup[] buffList = readDerivedByClusterVisIdx( Authorization,
			ClusterId,
			IsVisible );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a00c" ) ) {
				filteredList.add( (ICFSecSecGroup)buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecGroup[0] ) );
	}

	public ICFSecSecGroup readBuffByUNameIdx( ICFSecAuthorization Authorization,
		long ClusterId,
		String Name )
	{
		final String S_ProcName = "CFSecRamSecGroup.readBuffByUNameIdx() ";
		ICFSecSecGroup buff = readDerivedByUNameIdx( Authorization,
			ClusterId,
			Name );
		if( ( buff != null ) && buff.getClassCode().equals( "a00c" ) ) {
			return( (ICFSecSecGroup)buff );
		}
		else {
			return( null );
		}
	}

	public void updateSecGroup( ICFSecAuthorization Authorization,
		ICFSecSecGroup Buff )
	{
		CFLibDbKeyHash256 pkey = schema.getFactorySecGroup().newPKey();
		pkey.setRequiredSecGroupId( Buff.getRequiredSecGroupId() );
		ICFSecSecGroup existing = dictByPKey.get( pkey );
		if( existing == null ) {
			throw new CFLibStaleCacheDetectedException( getClass(),
				"updateSecGroup",
				"Existing record not found",
				"SecGroup",
				pkey );
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() ) {
			throw new CFLibCollisionDetectedException( getClass(),
				"updateSecGroup",
				pkey );
		}
		Buff.setRequiredRevision( Buff.getRequiredRevision() + 1 );
		CFSecBuffSecGroupByClusterIdxKey existingKeyClusterIdx = schema.getFactorySecGroup().newClusterIdxKey();
		existingKeyClusterIdx.setRequiredClusterId( existing.getRequiredClusterId() );

		CFSecBuffSecGroupByClusterIdxKey newKeyClusterIdx = schema.getFactorySecGroup().newClusterIdxKey();
		newKeyClusterIdx.setRequiredClusterId( Buff.getRequiredClusterId() );

		CFSecBuffSecGroupByClusterVisIdxKey existingKeyClusterVisIdx = schema.getFactorySecGroup().newClusterVisIdxKey();
		existingKeyClusterVisIdx.setRequiredClusterId( existing.getRequiredClusterId() );
		existingKeyClusterVisIdx.setRequiredIsVisible( existing.getRequiredIsVisible() );

		CFSecBuffSecGroupByClusterVisIdxKey newKeyClusterVisIdx = schema.getFactorySecGroup().newClusterVisIdxKey();
		newKeyClusterVisIdx.setRequiredClusterId( Buff.getRequiredClusterId() );
		newKeyClusterVisIdx.setRequiredIsVisible( Buff.getRequiredIsVisible() );

		CFSecBuffSecGroupByUNameIdxKey existingKeyUNameIdx = schema.getFactorySecGroup().newUNameIdxKey();
		existingKeyUNameIdx.setRequiredClusterId( existing.getRequiredClusterId() );
		existingKeyUNameIdx.setRequiredName( existing.getRequiredName() );

		CFSecBuffSecGroupByUNameIdxKey newKeyUNameIdx = schema.getFactorySecGroup().newUNameIdxKey();
		newKeyUNameIdx.setRequiredClusterId( Buff.getRequiredClusterId() );
		newKeyUNameIdx.setRequiredName( Buff.getRequiredName() );

		// Check unique indexes

		if( ! existingKeyUNameIdx.equals( newKeyUNameIdx ) ) {
			if( dictByUNameIdx.containsKey( newKeyUNameIdx ) ) {
				throw new CFLibUniqueIndexViolationException( getClass(),
					"updateSecGroup",
					"SecGroupUNameIdx",
					newKeyUNameIdx );
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
						"updateSecGroup",
						"Container",
						"SecGroupCluster",
						"Cluster",
						null );
				}
			}
		}

		// Update is valid

		Map< CFLibDbKeyHash256, CFSecBuffSecGroup > subdict;

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
			subdict = new HashMap< CFLibDbKeyHash256, CFSecBuffSecGroup >();
			dictByClusterIdx.put( newKeyClusterIdx, subdict );
		}
		subdict.put( pkey, Buff );

		subdict = dictByClusterVisIdx.get( existingKeyClusterVisIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictByClusterVisIdx.containsKey( newKeyClusterVisIdx ) ) {
			subdict = dictByClusterVisIdx.get( newKeyClusterVisIdx );
		}
		else {
			subdict = new HashMap< CFLibDbKeyHash256, CFSecBuffSecGroup >();
			dictByClusterVisIdx.put( newKeyClusterVisIdx, subdict );
		}
		subdict.put( pkey, Buff );

		dictByUNameIdx.remove( existingKeyUNameIdx );
		dictByUNameIdx.put( newKeyUNameIdx, Buff );

	}

	public void deleteSecGroup( ICFSecAuthorization Authorization,
		ICFSecSecGroup Buff )
	{
		final String S_ProcName = "CFSecRamSecGroupTable.deleteSecGroup() ";
		String classCode;
		CFLibDbKeyHash256 pkey = schema.getFactorySecGroup().newPKey();
		pkey.setRequiredSecGroupId( Buff.getRequiredSecGroupId() );
		ICFSecSecGroup existing = dictByPKey.get( pkey );
		if( existing == null ) {
			return;
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() )
		{
			throw new CFLibCollisionDetectedException( getClass(),
				"deleteSecGroup",
				pkey );
		}
					schema.getTableSecGrpInc().deleteSecGrpIncByIncludeIdx( Authorization,
						existing.getRequiredSecGroupId() );
					schema.getTableSecGrpMemb().deleteSecGrpMembByGroupIdx( Authorization,
						existing.getRequiredSecGroupId() );
					schema.getTableSecGrpInc().deleteSecGrpIncByGroupIdx( Authorization,
						existing.getRequiredSecGroupId() );
		CFSecBuffSecGroupByClusterIdxKey keyClusterIdx = schema.getFactorySecGroup().newClusterIdxKey();
		keyClusterIdx.setRequiredClusterId( existing.getRequiredClusterId() );

		CFSecBuffSecGroupByClusterVisIdxKey keyClusterVisIdx = schema.getFactorySecGroup().newClusterVisIdxKey();
		keyClusterVisIdx.setRequiredClusterId( existing.getRequiredClusterId() );
		keyClusterVisIdx.setRequiredIsVisible( existing.getRequiredIsVisible() );

		CFSecBuffSecGroupByUNameIdxKey keyUNameIdx = schema.getFactorySecGroup().newUNameIdxKey();
		keyUNameIdx.setRequiredClusterId( existing.getRequiredClusterId() );
		keyUNameIdx.setRequiredName( existing.getRequiredName() );

		// Validate reverse foreign keys

		// Delete is valid
		Map< CFLibDbKeyHash256, CFSecBuffSecGroup > subdict;

		dictByPKey.remove( pkey );

		subdict = dictByClusterIdx.get( keyClusterIdx );
		subdict.remove( pkey );

		subdict = dictByClusterVisIdx.get( keyClusterVisIdx );
		subdict.remove( pkey );

		dictByUNameIdx.remove( keyUNameIdx );

	}
	public void deleteSecGroupByIdIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argSecGroupId )
	{
		CFLibDbKeyHash256 key = schema.getFactorySecGroup().newPKey();
		key.setRequiredSecGroupId( argSecGroupId );
		deleteSecGroupByIdIdx( Authorization, key );
	}

	public void deleteSecGroupByIdIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argKey )
	{
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		ICFSecSecGroup cur;
		LinkedList<ICFSecSecGroup> matchSet = new LinkedList<ICFSecSecGroup>();
		Iterator<ICFSecSecGroup> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<ICFSecSecGroup> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableSecGroup().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecGroupId() );
			deleteSecGroup( Authorization, cur );
		}
	}

	public void deleteSecGroupByClusterIdx( ICFSecAuthorization Authorization,
		long argClusterId )
	{
		CFSecBuffSecGroupByClusterIdxKey key = schema.getFactorySecGroup().newClusterIdxKey();
		key.setRequiredClusterId( argClusterId );
		deleteSecGroupByClusterIdx( Authorization, key );
	}

	public void deleteSecGroupByClusterIdx( ICFSecAuthorization Authorization,
		ICFSecSecGroupByClusterIdxKey argKey )
	{
		ICFSecSecGroup cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<ICFSecSecGroup> matchSet = new LinkedList<ICFSecSecGroup>();
		Iterator<ICFSecSecGroup> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<ICFSecSecGroup> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableSecGroup().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecGroupId() );
			deleteSecGroup( Authorization, cur );
		}
	}

	public void deleteSecGroupByClusterVisIdx( ICFSecAuthorization Authorization,
		long argClusterId,
		boolean argIsVisible )
	{
		CFSecBuffSecGroupByClusterVisIdxKey key = schema.getFactorySecGroup().newClusterVisIdxKey();
		key.setRequiredClusterId( argClusterId );
		key.setRequiredIsVisible( argIsVisible );
		deleteSecGroupByClusterVisIdx( Authorization, key );
	}

	public void deleteSecGroupByClusterVisIdx( ICFSecAuthorization Authorization,
		ICFSecSecGroupByClusterVisIdxKey argKey )
	{
		ICFSecSecGroup cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<ICFSecSecGroup> matchSet = new LinkedList<ICFSecSecGroup>();
		Iterator<ICFSecSecGroup> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<ICFSecSecGroup> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableSecGroup().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecGroupId() );
			deleteSecGroup( Authorization, cur );
		}
	}

	public void deleteSecGroupByUNameIdx( ICFSecAuthorization Authorization,
		long argClusterId,
		String argName )
	{
		CFSecBuffSecGroupByUNameIdxKey key = schema.getFactorySecGroup().newUNameIdxKey();
		key.setRequiredClusterId( argClusterId );
		key.setRequiredName( argName );
		deleteSecGroupByUNameIdx( Authorization, key );
	}

	public void deleteSecGroupByUNameIdx( ICFSecAuthorization Authorization,
		ICFSecSecGroupByUNameIdxKey argKey )
	{
		ICFSecSecGroup cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<ICFSecSecGroup> matchSet = new LinkedList<ICFSecSecGroup>();
		Iterator<ICFSecSecGroup> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<ICFSecSecGroup> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableSecGroup().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecGroupId() );
			deleteSecGroup( Authorization, cur );
		}
	}
}
