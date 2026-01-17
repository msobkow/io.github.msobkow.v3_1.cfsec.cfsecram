
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
import java.util.*;
import org.apache.commons.codec.binary.Base64;
import io.github.msobkow.v3_1.cflib.*;
import io.github.msobkow.v3_1.cflib.dbutil.*;

import io.github.msobkow.v3_1.cfsec.cfsec.*;
import io.github.msobkow.v3_1.cfsec.cfsecobj.*;
import io.github.msobkow.v3_1.cfsec.cfsecobj.*;

/*
 *	CFSecRamSecGroupTable in-memory RAM DbIO implementation
 *	for SecGroup.
 */
public class CFSecRamSecGroupTable
	implements ICFSecSecGroupTable
{
	private ICFSecSchema schema;
	private Map< CFSecSecGroupPKey,
				CFSecSecGroupBuff > dictByPKey
		= new HashMap< CFSecSecGroupPKey,
				CFSecSecGroupBuff >();
	private Map< CFSecSecGroupByClusterIdxKey,
				Map< CFSecSecGroupPKey,
					CFSecSecGroupBuff >> dictByClusterIdx
		= new HashMap< CFSecSecGroupByClusterIdxKey,
				Map< CFSecSecGroupPKey,
					CFSecSecGroupBuff >>();
	private Map< CFSecSecGroupByClusterVisIdxKey,
				Map< CFSecSecGroupPKey,
					CFSecSecGroupBuff >> dictByClusterVisIdx
		= new HashMap< CFSecSecGroupByClusterVisIdxKey,
				Map< CFSecSecGroupPKey,
					CFSecSecGroupBuff >>();
	private Map< CFSecSecGroupByUNameIdxKey,
			CFSecSecGroupBuff > dictByUNameIdx
		= new HashMap< CFSecSecGroupByUNameIdxKey,
			CFSecSecGroupBuff >();

	public CFSecRamSecGroupTable( ICFSecSchema argSchema ) {
		schema = argSchema;
	}

	public void createSecGroup( CFSecAuthorization Authorization,
		CFSecSecGroupBuff Buff )
	{
		final String S_ProcName = "createSecGroup";
		CFSecSecGroupPKey pkey = schema.getFactorySecGroup().newPKey();
		pkey.setRequiredSecGroupId( schema.nextSecGroupIdGen() );
		Buff.setRequiredSecGroupId( pkey.getRequiredSecGroupId() );
		CFSecSecGroupByClusterIdxKey keyClusterIdx = schema.getFactorySecGroup().newClusterIdxKey();
		keyClusterIdx.setRequiredClusterId( Buff.getRequiredClusterId() );

		CFSecSecGroupByClusterVisIdxKey keyClusterVisIdx = schema.getFactorySecGroup().newClusterVisIdxKey();
		keyClusterVisIdx.setRequiredClusterId( Buff.getRequiredClusterId() );
		keyClusterVisIdx.setRequiredIsVisible( Buff.getRequiredIsVisible() );

		CFSecSecGroupByUNameIdxKey keyUNameIdx = schema.getFactorySecGroup().newUNameIdxKey();
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

		Map< CFSecSecGroupPKey, CFSecSecGroupBuff > subdictClusterIdx;
		if( dictByClusterIdx.containsKey( keyClusterIdx ) ) {
			subdictClusterIdx = dictByClusterIdx.get( keyClusterIdx );
		}
		else {
			subdictClusterIdx = new HashMap< CFSecSecGroupPKey, CFSecSecGroupBuff >();
			dictByClusterIdx.put( keyClusterIdx, subdictClusterIdx );
		}
		subdictClusterIdx.put( pkey, Buff );

		Map< CFSecSecGroupPKey, CFSecSecGroupBuff > subdictClusterVisIdx;
		if( dictByClusterVisIdx.containsKey( keyClusterVisIdx ) ) {
			subdictClusterVisIdx = dictByClusterVisIdx.get( keyClusterVisIdx );
		}
		else {
			subdictClusterVisIdx = new HashMap< CFSecSecGroupPKey, CFSecSecGroupBuff >();
			dictByClusterVisIdx.put( keyClusterVisIdx, subdictClusterVisIdx );
		}
		subdictClusterVisIdx.put( pkey, Buff );

		dictByUNameIdx.put( keyUNameIdx, Buff );

	}

	public CFSecSecGroupBuff readDerived( CFSecAuthorization Authorization,
		CFSecSecGroupPKey PKey )
	{
		final String S_ProcName = "CFSecRamSecGroup.readDerived";
		CFSecSecGroupPKey key = schema.getFactorySecGroup().newPKey();
		key.setRequiredSecGroupId( PKey.getRequiredSecGroupId() );
		CFSecSecGroupBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecSecGroupBuff lockDerived( CFSecAuthorization Authorization,
		CFSecSecGroupPKey PKey )
	{
		final String S_ProcName = "CFSecRamSecGroup.readDerived";
		CFSecSecGroupPKey key = schema.getFactorySecGroup().newPKey();
		key.setRequiredSecGroupId( PKey.getRequiredSecGroupId() );
		CFSecSecGroupBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecSecGroupBuff[] readAllDerived( CFSecAuthorization Authorization ) {
		final String S_ProcName = "CFSecRamSecGroup.readAllDerived";
		CFSecSecGroupBuff[] retList = new CFSecSecGroupBuff[ dictByPKey.values().size() ];
		Iterator< CFSecSecGroupBuff > iter = dictByPKey.values().iterator();
		int idx = 0;
		while( iter.hasNext() ) {
			retList[ idx++ ] = iter.next();
		}
		return( retList );
	}

	public CFSecSecGroupBuff[] readDerivedByClusterIdx( CFSecAuthorization Authorization,
		long ClusterId )
	{
		final String S_ProcName = "CFSecRamSecGroup.readDerivedByClusterIdx";
		CFSecSecGroupByClusterIdxKey key = schema.getFactorySecGroup().newClusterIdxKey();
		key.setRequiredClusterId( ClusterId );

		CFSecSecGroupBuff[] recArray;
		if( dictByClusterIdx.containsKey( key ) ) {
			Map< CFSecSecGroupPKey, CFSecSecGroupBuff > subdictClusterIdx
				= dictByClusterIdx.get( key );
			recArray = new CFSecSecGroupBuff[ subdictClusterIdx.size() ];
			Iterator< CFSecSecGroupBuff > iter = subdictClusterIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFSecSecGroupPKey, CFSecSecGroupBuff > subdictClusterIdx
				= new HashMap< CFSecSecGroupPKey, CFSecSecGroupBuff >();
			dictByClusterIdx.put( key, subdictClusterIdx );
			recArray = new CFSecSecGroupBuff[0];
		}
		return( recArray );
	}

	public CFSecSecGroupBuff[] readDerivedByClusterVisIdx( CFSecAuthorization Authorization,
		long ClusterId,
		boolean IsVisible )
	{
		final String S_ProcName = "CFSecRamSecGroup.readDerivedByClusterVisIdx";
		CFSecSecGroupByClusterVisIdxKey key = schema.getFactorySecGroup().newClusterVisIdxKey();
		key.setRequiredClusterId( ClusterId );
		key.setRequiredIsVisible( IsVisible );

		CFSecSecGroupBuff[] recArray;
		if( dictByClusterVisIdx.containsKey( key ) ) {
			Map< CFSecSecGroupPKey, CFSecSecGroupBuff > subdictClusterVisIdx
				= dictByClusterVisIdx.get( key );
			recArray = new CFSecSecGroupBuff[ subdictClusterVisIdx.size() ];
			Iterator< CFSecSecGroupBuff > iter = subdictClusterVisIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFSecSecGroupPKey, CFSecSecGroupBuff > subdictClusterVisIdx
				= new HashMap< CFSecSecGroupPKey, CFSecSecGroupBuff >();
			dictByClusterVisIdx.put( key, subdictClusterVisIdx );
			recArray = new CFSecSecGroupBuff[0];
		}
		return( recArray );
	}

	public CFSecSecGroupBuff readDerivedByUNameIdx( CFSecAuthorization Authorization,
		long ClusterId,
		String Name )
	{
		final String S_ProcName = "CFSecRamSecGroup.readDerivedByUNameIdx";
		CFSecSecGroupByUNameIdxKey key = schema.getFactorySecGroup().newUNameIdxKey();
		key.setRequiredClusterId( ClusterId );
		key.setRequiredName( Name );

		CFSecSecGroupBuff buff;
		if( dictByUNameIdx.containsKey( key ) ) {
			buff = dictByUNameIdx.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecSecGroupBuff readDerivedByIdIdx( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecGroupId )
	{
		final String S_ProcName = "CFSecRamSecGroup.readDerivedByIdIdx() ";
		CFSecSecGroupPKey key = schema.getFactorySecGroup().newPKey();
		key.setRequiredSecGroupId( SecGroupId );

		CFSecSecGroupBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecSecGroupBuff readBuff( CFSecAuthorization Authorization,
		CFSecSecGroupPKey PKey )
	{
		final String S_ProcName = "CFSecRamSecGroup.readBuff";
		CFSecSecGroupBuff buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( ! buff.getClassCode().equals( "a00c" ) ) ) {
			buff = null;
		}
		return( buff );
	}

	public CFSecSecGroupBuff lockBuff( CFSecAuthorization Authorization,
		CFSecSecGroupPKey PKey )
	{
		final String S_ProcName = "lockBuff";
		CFSecSecGroupBuff buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( ! buff.getClassCode().equals( "a00c" ) ) ) {
			buff = null;
		}
		return( buff );
	}

	public CFSecSecGroupBuff[] readAllBuff( CFSecAuthorization Authorization )
	{
		final String S_ProcName = "CFSecRamSecGroup.readAllBuff";
		CFSecSecGroupBuff buff;
		ArrayList<CFSecSecGroupBuff> filteredList = new ArrayList<CFSecSecGroupBuff>();
		CFSecSecGroupBuff[] buffList = readAllDerived( Authorization );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a00c" ) ) {
				filteredList.add( buff );
			}
		}
		return( filteredList.toArray( new CFSecSecGroupBuff[0] ) );
	}

	public CFSecSecGroupBuff readBuffByIdIdx( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecGroupId )
	{
		final String S_ProcName = "CFSecRamSecGroup.readBuffByIdIdx() ";
		CFSecSecGroupBuff buff = readDerivedByIdIdx( Authorization,
			SecGroupId );
		if( ( buff != null ) && buff.getClassCode().equals( "a00c" ) ) {
			return( (CFSecSecGroupBuff)buff );
		}
		else {
			return( null );
		}
	}

	public CFSecSecGroupBuff[] readBuffByClusterIdx( CFSecAuthorization Authorization,
		long ClusterId )
	{
		final String S_ProcName = "CFSecRamSecGroup.readBuffByClusterIdx() ";
		CFSecSecGroupBuff buff;
		ArrayList<CFSecSecGroupBuff> filteredList = new ArrayList<CFSecSecGroupBuff>();
		CFSecSecGroupBuff[] buffList = readDerivedByClusterIdx( Authorization,
			ClusterId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a00c" ) ) {
				filteredList.add( (CFSecSecGroupBuff)buff );
			}
		}
		return( filteredList.toArray( new CFSecSecGroupBuff[0] ) );
	}

	public CFSecSecGroupBuff[] readBuffByClusterVisIdx( CFSecAuthorization Authorization,
		long ClusterId,
		boolean IsVisible )
	{
		final String S_ProcName = "CFSecRamSecGroup.readBuffByClusterVisIdx() ";
		CFSecSecGroupBuff buff;
		ArrayList<CFSecSecGroupBuff> filteredList = new ArrayList<CFSecSecGroupBuff>();
		CFSecSecGroupBuff[] buffList = readDerivedByClusterVisIdx( Authorization,
			ClusterId,
			IsVisible );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a00c" ) ) {
				filteredList.add( (CFSecSecGroupBuff)buff );
			}
		}
		return( filteredList.toArray( new CFSecSecGroupBuff[0] ) );
	}

	public CFSecSecGroupBuff readBuffByUNameIdx( CFSecAuthorization Authorization,
		long ClusterId,
		String Name )
	{
		final String S_ProcName = "CFSecRamSecGroup.readBuffByUNameIdx() ";
		CFSecSecGroupBuff buff = readDerivedByUNameIdx( Authorization,
			ClusterId,
			Name );
		if( ( buff != null ) && buff.getClassCode().equals( "a00c" ) ) {
			return( (CFSecSecGroupBuff)buff );
		}
		else {
			return( null );
		}
	}

	public void updateSecGroup( CFSecAuthorization Authorization,
		CFSecSecGroupBuff Buff )
	{
		CFSecSecGroupPKey pkey = schema.getFactorySecGroup().newPKey();
		pkey.setRequiredSecGroupId( Buff.getRequiredSecGroupId() );
		CFSecSecGroupBuff existing = dictByPKey.get( pkey );
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
		CFSecSecGroupByClusterIdxKey existingKeyClusterIdx = schema.getFactorySecGroup().newClusterIdxKey();
		existingKeyClusterIdx.setRequiredClusterId( existing.getRequiredClusterId() );

		CFSecSecGroupByClusterIdxKey newKeyClusterIdx = schema.getFactorySecGroup().newClusterIdxKey();
		newKeyClusterIdx.setRequiredClusterId( Buff.getRequiredClusterId() );

		CFSecSecGroupByClusterVisIdxKey existingKeyClusterVisIdx = schema.getFactorySecGroup().newClusterVisIdxKey();
		existingKeyClusterVisIdx.setRequiredClusterId( existing.getRequiredClusterId() );
		existingKeyClusterVisIdx.setRequiredIsVisible( existing.getRequiredIsVisible() );

		CFSecSecGroupByClusterVisIdxKey newKeyClusterVisIdx = schema.getFactorySecGroup().newClusterVisIdxKey();
		newKeyClusterVisIdx.setRequiredClusterId( Buff.getRequiredClusterId() );
		newKeyClusterVisIdx.setRequiredIsVisible( Buff.getRequiredIsVisible() );

		CFSecSecGroupByUNameIdxKey existingKeyUNameIdx = schema.getFactorySecGroup().newUNameIdxKey();
		existingKeyUNameIdx.setRequiredClusterId( existing.getRequiredClusterId() );
		existingKeyUNameIdx.setRequiredName( existing.getRequiredName() );

		CFSecSecGroupByUNameIdxKey newKeyUNameIdx = schema.getFactorySecGroup().newUNameIdxKey();
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

		Map< CFSecSecGroupPKey, CFSecSecGroupBuff > subdict;

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
			subdict = new HashMap< CFSecSecGroupPKey, CFSecSecGroupBuff >();
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
			subdict = new HashMap< CFSecSecGroupPKey, CFSecSecGroupBuff >();
			dictByClusterVisIdx.put( newKeyClusterVisIdx, subdict );
		}
		subdict.put( pkey, Buff );

		dictByUNameIdx.remove( existingKeyUNameIdx );
		dictByUNameIdx.put( newKeyUNameIdx, Buff );

	}

	public void deleteSecGroup( CFSecAuthorization Authorization,
		CFSecSecGroupBuff Buff )
	{
		final String S_ProcName = "CFSecRamSecGroupTable.deleteSecGroup() ";
		String classCode;
		CFSecSecGroupPKey pkey = schema.getFactorySecGroup().newPKey();
		pkey.setRequiredSecGroupId( Buff.getRequiredSecGroupId() );
		CFSecSecGroupBuff existing = dictByPKey.get( pkey );
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
		CFSecSecGroupByClusterIdxKey keyClusterIdx = schema.getFactorySecGroup().newClusterIdxKey();
		keyClusterIdx.setRequiredClusterId( existing.getRequiredClusterId() );

		CFSecSecGroupByClusterVisIdxKey keyClusterVisIdx = schema.getFactorySecGroup().newClusterVisIdxKey();
		keyClusterVisIdx.setRequiredClusterId( existing.getRequiredClusterId() );
		keyClusterVisIdx.setRequiredIsVisible( existing.getRequiredIsVisible() );

		CFSecSecGroupByUNameIdxKey keyUNameIdx = schema.getFactorySecGroup().newUNameIdxKey();
		keyUNameIdx.setRequiredClusterId( existing.getRequiredClusterId() );
		keyUNameIdx.setRequiredName( existing.getRequiredName() );

		// Validate reverse foreign keys

		// Delete is valid
		Map< CFSecSecGroupPKey, CFSecSecGroupBuff > subdict;

		dictByPKey.remove( pkey );

		subdict = dictByClusterIdx.get( keyClusterIdx );
		subdict.remove( pkey );

		subdict = dictByClusterVisIdx.get( keyClusterVisIdx );
		subdict.remove( pkey );

		dictByUNameIdx.remove( keyUNameIdx );

	}
	public void deleteSecGroupByIdIdx( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 argSecGroupId )
	{
		CFSecSecGroupPKey key = schema.getFactorySecGroup().newPKey();
		key.setRequiredSecGroupId( argSecGroupId );
		deleteSecGroupByIdIdx( Authorization, key );
	}

	public void deleteSecGroupByIdIdx( CFSecAuthorization Authorization,
		CFSecSecGroupPKey argKey )
	{
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		CFSecSecGroupBuff cur;
		LinkedList<CFSecSecGroupBuff> matchSet = new LinkedList<CFSecSecGroupBuff>();
		Iterator<CFSecSecGroupBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecSecGroupBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableSecGroup().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecGroupId() );
			deleteSecGroup( Authorization, cur );
		}
	}

	public void deleteSecGroupByClusterIdx( CFSecAuthorization Authorization,
		long argClusterId )
	{
		CFSecSecGroupByClusterIdxKey key = schema.getFactorySecGroup().newClusterIdxKey();
		key.setRequiredClusterId( argClusterId );
		deleteSecGroupByClusterIdx( Authorization, key );
	}

	public void deleteSecGroupByClusterIdx( CFSecAuthorization Authorization,
		CFSecSecGroupByClusterIdxKey argKey )
	{
		CFSecSecGroupBuff cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecSecGroupBuff> matchSet = new LinkedList<CFSecSecGroupBuff>();
		Iterator<CFSecSecGroupBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecSecGroupBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableSecGroup().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecGroupId() );
			deleteSecGroup( Authorization, cur );
		}
	}

	public void deleteSecGroupByClusterVisIdx( CFSecAuthorization Authorization,
		long argClusterId,
		boolean argIsVisible )
	{
		CFSecSecGroupByClusterVisIdxKey key = schema.getFactorySecGroup().newClusterVisIdxKey();
		key.setRequiredClusterId( argClusterId );
		key.setRequiredIsVisible( argIsVisible );
		deleteSecGroupByClusterVisIdx( Authorization, key );
	}

	public void deleteSecGroupByClusterVisIdx( CFSecAuthorization Authorization,
		CFSecSecGroupByClusterVisIdxKey argKey )
	{
		CFSecSecGroupBuff cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecSecGroupBuff> matchSet = new LinkedList<CFSecSecGroupBuff>();
		Iterator<CFSecSecGroupBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecSecGroupBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableSecGroup().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecGroupId() );
			deleteSecGroup( Authorization, cur );
		}
	}

	public void deleteSecGroupByUNameIdx( CFSecAuthorization Authorization,
		long argClusterId,
		String argName )
	{
		CFSecSecGroupByUNameIdxKey key = schema.getFactorySecGroup().newUNameIdxKey();
		key.setRequiredClusterId( argClusterId );
		key.setRequiredName( argName );
		deleteSecGroupByUNameIdx( Authorization, key );
	}

	public void deleteSecGroupByUNameIdx( CFSecAuthorization Authorization,
		CFSecSecGroupByUNameIdxKey argKey )
	{
		CFSecSecGroupBuff cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecSecGroupBuff> matchSet = new LinkedList<CFSecSecGroupBuff>();
		Iterator<CFSecSecGroupBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecSecGroupBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableSecGroup().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecGroupId() );
			deleteSecGroup( Authorization, cur );
		}
	}
}
