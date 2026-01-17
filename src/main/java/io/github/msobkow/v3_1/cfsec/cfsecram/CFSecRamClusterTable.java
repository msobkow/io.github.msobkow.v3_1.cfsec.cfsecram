
// Description: Java 25 in-memory RAM DbIO implementation for Cluster.

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
 *	CFSecRamClusterTable in-memory RAM DbIO implementation
 *	for Cluster.
 */
public class CFSecRamClusterTable
	implements ICFSecClusterTable
{
	private ICFSecSchema schema;
	private Map< CFSecClusterPKey,
				CFSecClusterBuff > dictByPKey
		= new HashMap< CFSecClusterPKey,
				CFSecClusterBuff >();
	private Map< CFSecClusterByUDomNameIdxKey,
			CFSecClusterBuff > dictByUDomNameIdx
		= new HashMap< CFSecClusterByUDomNameIdxKey,
			CFSecClusterBuff >();
	private Map< CFSecClusterByUDescrIdxKey,
			CFSecClusterBuff > dictByUDescrIdx
		= new HashMap< CFSecClusterByUDescrIdxKey,
			CFSecClusterBuff >();

	public CFSecRamClusterTable( ICFSecSchema argSchema ) {
		schema = argSchema;
	}

	public void createCluster( CFSecAuthorization Authorization,
		CFSecClusterBuff Buff )
	{
		final String S_ProcName = "createCluster";
		CFSecClusterPKey pkey = schema.getFactoryCluster().newPKey();
		pkey.setRequiredId( schema.nextClusterIdGen() );
		Buff.setRequiredId( pkey.getRequiredId() );
		CFSecClusterByUDomNameIdxKey keyUDomNameIdx = schema.getFactoryCluster().newUDomNameIdxKey();
		keyUDomNameIdx.setRequiredFullDomName( Buff.getRequiredFullDomName() );

		CFSecClusterByUDescrIdxKey keyUDescrIdx = schema.getFactoryCluster().newUDescrIdxKey();
		keyUDescrIdx.setRequiredDescription( Buff.getRequiredDescription() );

		// Validate unique indexes

		if( dictByPKey.containsKey( pkey ) ) {
			throw new CFLibPrimaryKeyNotNewException( getClass(), S_ProcName, pkey );
		}

		if( dictByUDomNameIdx.containsKey( keyUDomNameIdx ) ) {
			throw new CFLibUniqueIndexViolationException( getClass(),
				S_ProcName,
				"ClusterUDomNameIdx",
				keyUDomNameIdx );
		}

		if( dictByUDescrIdx.containsKey( keyUDescrIdx ) ) {
			throw new CFLibUniqueIndexViolationException( getClass(),
				S_ProcName,
				"ClusterUDescrNameIdx",
				keyUDescrIdx );
		}

		// Validate foreign keys

		// Proceed with adding the new record

		dictByPKey.put( pkey, Buff );

		dictByUDomNameIdx.put( keyUDomNameIdx, Buff );

		dictByUDescrIdx.put( keyUDescrIdx, Buff );

	}

	public CFSecClusterBuff readDerived( CFSecAuthorization Authorization,
		CFSecClusterPKey PKey )
	{
		final String S_ProcName = "CFSecRamCluster.readDerived";
		CFSecClusterPKey key = schema.getFactoryCluster().newPKey();
		key.setRequiredId( PKey.getRequiredId() );
		CFSecClusterBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecClusterBuff lockDerived( CFSecAuthorization Authorization,
		CFSecClusterPKey PKey )
	{
		final String S_ProcName = "CFSecRamCluster.readDerived";
		CFSecClusterPKey key = schema.getFactoryCluster().newPKey();
		key.setRequiredId( PKey.getRequiredId() );
		CFSecClusterBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecClusterBuff[] readAllDerived( CFSecAuthorization Authorization ) {
		final String S_ProcName = "CFSecRamCluster.readAllDerived";
		CFSecClusterBuff[] retList = new CFSecClusterBuff[ dictByPKey.values().size() ];
		Iterator< CFSecClusterBuff > iter = dictByPKey.values().iterator();
		int idx = 0;
		while( iter.hasNext() ) {
			retList[ idx++ ] = iter.next();
		}
		return( retList );
	}

	public CFSecClusterBuff readDerivedByUDomNameIdx( CFSecAuthorization Authorization,
		String FullDomName )
	{
		final String S_ProcName = "CFSecRamCluster.readDerivedByUDomNameIdx";
		CFSecClusterByUDomNameIdxKey key = schema.getFactoryCluster().newUDomNameIdxKey();
		key.setRequiredFullDomName( FullDomName );

		CFSecClusterBuff buff;
		if( dictByUDomNameIdx.containsKey( key ) ) {
			buff = dictByUDomNameIdx.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecClusterBuff readDerivedByUDescrIdx( CFSecAuthorization Authorization,
		String Description )
	{
		final String S_ProcName = "CFSecRamCluster.readDerivedByUDescrIdx";
		CFSecClusterByUDescrIdxKey key = schema.getFactoryCluster().newUDescrIdxKey();
		key.setRequiredDescription( Description );

		CFSecClusterBuff buff;
		if( dictByUDescrIdx.containsKey( key ) ) {
			buff = dictByUDescrIdx.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecClusterBuff readDerivedByIdIdx( CFSecAuthorization Authorization,
		long Id )
	{
		final String S_ProcName = "CFSecRamCluster.readDerivedByIdIdx() ";
		CFSecClusterPKey key = schema.getFactoryCluster().newPKey();
		key.setRequiredId( Id );

		CFSecClusterBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecClusterBuff readBuff( CFSecAuthorization Authorization,
		CFSecClusterPKey PKey )
	{
		final String S_ProcName = "CFSecRamCluster.readBuff";
		CFSecClusterBuff buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( ! buff.getClassCode().equals( "a001" ) ) ) {
			buff = null;
		}
		return( buff );
	}

	public CFSecClusterBuff lockBuff( CFSecAuthorization Authorization,
		CFSecClusterPKey PKey )
	{
		final String S_ProcName = "lockBuff";
		CFSecClusterBuff buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( ! buff.getClassCode().equals( "a001" ) ) ) {
			buff = null;
		}
		return( buff );
	}

	public CFSecClusterBuff[] readAllBuff( CFSecAuthorization Authorization )
	{
		final String S_ProcName = "CFSecRamCluster.readAllBuff";
		CFSecClusterBuff buff;
		ArrayList<CFSecClusterBuff> filteredList = new ArrayList<CFSecClusterBuff>();
		CFSecClusterBuff[] buffList = readAllDerived( Authorization );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a001" ) ) {
				filteredList.add( buff );
			}
		}
		return( filteredList.toArray( new CFSecClusterBuff[0] ) );
	}

	/**
	 *	Read a page of all the specific Cluster buffer instances.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@return All the specific Cluster instances in the database accessible for the Authorization.
	 */
	public CFSecClusterBuff[] pageAllBuff( CFSecAuthorization Authorization,
		Long priorId )
	{
		final String S_ProcName = "pageAllBuff";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	public CFSecClusterBuff readBuffByIdIdx( CFSecAuthorization Authorization,
		long Id )
	{
		final String S_ProcName = "CFSecRamCluster.readBuffByIdIdx() ";
		CFSecClusterBuff buff = readDerivedByIdIdx( Authorization,
			Id );
		if( ( buff != null ) && buff.getClassCode().equals( "a001" ) ) {
			return( (CFSecClusterBuff)buff );
		}
		else {
			return( null );
		}
	}

	public CFSecClusterBuff readBuffByUDomNameIdx( CFSecAuthorization Authorization,
		String FullDomName )
	{
		final String S_ProcName = "CFSecRamCluster.readBuffByUDomNameIdx() ";
		CFSecClusterBuff buff = readDerivedByUDomNameIdx( Authorization,
			FullDomName );
		if( ( buff != null ) && buff.getClassCode().equals( "a001" ) ) {
			return( (CFSecClusterBuff)buff );
		}
		else {
			return( null );
		}
	}

	public CFSecClusterBuff readBuffByUDescrIdx( CFSecAuthorization Authorization,
		String Description )
	{
		final String S_ProcName = "CFSecRamCluster.readBuffByUDescrIdx() ";
		CFSecClusterBuff buff = readDerivedByUDescrIdx( Authorization,
			Description );
		if( ( buff != null ) && buff.getClassCode().equals( "a001" ) ) {
			return( (CFSecClusterBuff)buff );
		}
		else {
			return( null );
		}
	}

	public void updateCluster( CFSecAuthorization Authorization,
		CFSecClusterBuff Buff )
	{
		CFSecClusterPKey pkey = schema.getFactoryCluster().newPKey();
		pkey.setRequiredId( Buff.getRequiredId() );
		CFSecClusterBuff existing = dictByPKey.get( pkey );
		if( existing == null ) {
			throw new CFLibStaleCacheDetectedException( getClass(),
				"updateCluster",
				"Existing record not found",
				"Cluster",
				pkey );
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() ) {
			throw new CFLibCollisionDetectedException( getClass(),
				"updateCluster",
				pkey );
		}
		Buff.setRequiredRevision( Buff.getRequiredRevision() + 1 );
		CFSecClusterByUDomNameIdxKey existingKeyUDomNameIdx = schema.getFactoryCluster().newUDomNameIdxKey();
		existingKeyUDomNameIdx.setRequiredFullDomName( existing.getRequiredFullDomName() );

		CFSecClusterByUDomNameIdxKey newKeyUDomNameIdx = schema.getFactoryCluster().newUDomNameIdxKey();
		newKeyUDomNameIdx.setRequiredFullDomName( Buff.getRequiredFullDomName() );

		CFSecClusterByUDescrIdxKey existingKeyUDescrIdx = schema.getFactoryCluster().newUDescrIdxKey();
		existingKeyUDescrIdx.setRequiredDescription( existing.getRequiredDescription() );

		CFSecClusterByUDescrIdxKey newKeyUDescrIdx = schema.getFactoryCluster().newUDescrIdxKey();
		newKeyUDescrIdx.setRequiredDescription( Buff.getRequiredDescription() );

		// Check unique indexes

		if( ! existingKeyUDomNameIdx.equals( newKeyUDomNameIdx ) ) {
			if( dictByUDomNameIdx.containsKey( newKeyUDomNameIdx ) ) {
				throw new CFLibUniqueIndexViolationException( getClass(),
					"updateCluster",
					"ClusterUDomNameIdx",
					newKeyUDomNameIdx );
			}
		}

		if( ! existingKeyUDescrIdx.equals( newKeyUDescrIdx ) ) {
			if( dictByUDescrIdx.containsKey( newKeyUDescrIdx ) ) {
				throw new CFLibUniqueIndexViolationException( getClass(),
					"updateCluster",
					"ClusterUDescrNameIdx",
					newKeyUDescrIdx );
			}
		}

		// Validate foreign keys

		// Update is valid

		Map< CFSecClusterPKey, CFSecClusterBuff > subdict;

		dictByPKey.remove( pkey );
		dictByPKey.put( pkey, Buff );

		dictByUDomNameIdx.remove( existingKeyUDomNameIdx );
		dictByUDomNameIdx.put( newKeyUDomNameIdx, Buff );

		dictByUDescrIdx.remove( existingKeyUDescrIdx );
		dictByUDescrIdx.put( newKeyUDescrIdx, Buff );

	}

	public void deleteCluster( CFSecAuthorization Authorization,
		CFSecClusterBuff Buff )
	{
		final String S_ProcName = "CFSecRamClusterTable.deleteCluster() ";
		String classCode;
		CFSecClusterPKey pkey = schema.getFactoryCluster().newPKey();
		pkey.setRequiredId( Buff.getRequiredId() );
		CFSecClusterBuff existing = dictByPKey.get( pkey );
		if( existing == null ) {
			return;
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() )
		{
			throw new CFLibCollisionDetectedException( getClass(),
				"deleteCluster",
				pkey );
		}
		CFSecSecGroupBuff buffDelSecGrpIncByGroup;
		CFSecSecGroupBuff arrDelSecGrpIncByGroup[] = schema.getTableSecGroup().readDerivedByClusterIdx( Authorization,
			existing.getRequiredId() );
		for( int idxDelSecGrpIncByGroup = 0; idxDelSecGrpIncByGroup < arrDelSecGrpIncByGroup.length; idxDelSecGrpIncByGroup++ ) {
			buffDelSecGrpIncByGroup = arrDelSecGrpIncByGroup[idxDelSecGrpIncByGroup];
					schema.getTableSecGrpInc().deleteSecGrpIncByIncludeIdx( Authorization,
						buffDelSecGrpIncByGroup.getRequiredSecGroupId() );
		}
		CFSecSecGroupBuff buffDelSecGrpMembs;
		CFSecSecGroupBuff arrDelSecGrpMembs[] = schema.getTableSecGroup().readDerivedByClusterIdx( Authorization,
			existing.getRequiredId() );
		for( int idxDelSecGrpMembs = 0; idxDelSecGrpMembs < arrDelSecGrpMembs.length; idxDelSecGrpMembs++ ) {
			buffDelSecGrpMembs = arrDelSecGrpMembs[idxDelSecGrpMembs];
					schema.getTableSecGrpMemb().deleteSecGrpMembByGroupIdx( Authorization,
						buffDelSecGrpMembs.getRequiredSecGroupId() );
		}
		CFSecSecGroupBuff buffDelSecGrpIncs;
		CFSecSecGroupBuff arrDelSecGrpIncs[] = schema.getTableSecGroup().readDerivedByClusterIdx( Authorization,
			existing.getRequiredId() );
		for( int idxDelSecGrpIncs = 0; idxDelSecGrpIncs < arrDelSecGrpIncs.length; idxDelSecGrpIncs++ ) {
			buffDelSecGrpIncs = arrDelSecGrpIncs[idxDelSecGrpIncs];
					schema.getTableSecGrpInc().deleteSecGrpIncByGroupIdx( Authorization,
						buffDelSecGrpIncs.getRequiredSecGroupId() );
		}
					schema.getTableSecGroup().deleteSecGroupByClusterIdx( Authorization,
						existing.getRequiredId() );
					schema.getTableTenant().deleteTenantByClusterIdx( Authorization,
						existing.getRequiredId() );
					schema.getTableHostNode().deleteHostNodeByClusterIdx( Authorization,
						existing.getRequiredId() );
		CFSecClusterByUDomNameIdxKey keyUDomNameIdx = schema.getFactoryCluster().newUDomNameIdxKey();
		keyUDomNameIdx.setRequiredFullDomName( existing.getRequiredFullDomName() );

		CFSecClusterByUDescrIdxKey keyUDescrIdx = schema.getFactoryCluster().newUDescrIdxKey();
		keyUDescrIdx.setRequiredDescription( existing.getRequiredDescription() );

		// Validate reverse foreign keys

		// Delete is valid
		Map< CFSecClusterPKey, CFSecClusterBuff > subdict;

		dictByPKey.remove( pkey );

		dictByUDomNameIdx.remove( keyUDomNameIdx );

		dictByUDescrIdx.remove( keyUDescrIdx );

	}
	public void deleteClusterByIdIdx( CFSecAuthorization Authorization,
		long argId )
	{
		CFSecClusterPKey key = schema.getFactoryCluster().newPKey();
		key.setRequiredId( argId );
		deleteClusterByIdIdx( Authorization, key );
	}

	public void deleteClusterByIdIdx( CFSecAuthorization Authorization,
		CFSecClusterPKey argKey )
	{
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		CFSecClusterBuff cur;
		LinkedList<CFSecClusterBuff> matchSet = new LinkedList<CFSecClusterBuff>();
		Iterator<CFSecClusterBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecClusterBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableCluster().readDerivedByIdIdx( Authorization,
				cur.getRequiredId() );
			deleteCluster( Authorization, cur );
		}
	}

	public void deleteClusterByUDomNameIdx( CFSecAuthorization Authorization,
		String argFullDomName )
	{
		CFSecClusterByUDomNameIdxKey key = schema.getFactoryCluster().newUDomNameIdxKey();
		key.setRequiredFullDomName( argFullDomName );
		deleteClusterByUDomNameIdx( Authorization, key );
	}

	public void deleteClusterByUDomNameIdx( CFSecAuthorization Authorization,
		CFSecClusterByUDomNameIdxKey argKey )
	{
		CFSecClusterBuff cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecClusterBuff> matchSet = new LinkedList<CFSecClusterBuff>();
		Iterator<CFSecClusterBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecClusterBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableCluster().readDerivedByIdIdx( Authorization,
				cur.getRequiredId() );
			deleteCluster( Authorization, cur );
		}
	}

	public void deleteClusterByUDescrIdx( CFSecAuthorization Authorization,
		String argDescription )
	{
		CFSecClusterByUDescrIdxKey key = schema.getFactoryCluster().newUDescrIdxKey();
		key.setRequiredDescription( argDescription );
		deleteClusterByUDescrIdx( Authorization, key );
	}

	public void deleteClusterByUDescrIdx( CFSecAuthorization Authorization,
		CFSecClusterByUDescrIdxKey argKey )
	{
		CFSecClusterBuff cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecClusterBuff> matchSet = new LinkedList<CFSecClusterBuff>();
		Iterator<CFSecClusterBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecClusterBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableCluster().readDerivedByIdIdx( Authorization,
				cur.getRequiredId() );
			deleteCluster( Authorization, cur );
		}
	}
}
