
// Description: Java 25 in-memory RAM DbIO implementation for HostNode.

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
 *	CFSecRamHostNodeTable in-memory RAM DbIO implementation
 *	for HostNode.
 */
public class CFSecRamHostNodeTable
	implements ICFSecHostNodeTable
{
	private ICFSecSchema schema;
	private Map< CFLibDbKeyHash256,
				CFSecBuffHostNode > dictByPKey
		= new HashMap< CFLibDbKeyHash256,
				CFSecBuffHostNode >();
	private Map< CFSecBuffHostNodeByClusterIdxKey,
				Map< CFLibDbKeyHash256,
					CFSecBuffHostNode >> dictByClusterIdx
		= new HashMap< CFSecBuffHostNodeByClusterIdxKey,
				Map< CFLibDbKeyHash256,
					CFSecBuffHostNode >>();
	private Map< CFSecBuffHostNodeByUDescrIdxKey,
			CFSecBuffHostNode > dictByUDescrIdx
		= new HashMap< CFSecBuffHostNodeByUDescrIdxKey,
			CFSecBuffHostNode >();
	private Map< CFSecBuffHostNodeByHostNameIdxKey,
			CFSecBuffHostNode > dictByHostNameIdx
		= new HashMap< CFSecBuffHostNodeByHostNameIdxKey,
			CFSecBuffHostNode >();

	public CFSecRamHostNodeTable( ICFSecSchema argSchema ) {
		schema = argSchema;
	}

	public void createHostNode( ICFSecAuthorization Authorization,
		ICFSecHostNode Buff )
	{
		final String S_ProcName = "createHostNode";
		CFLibDbKeyHash256 pkey = schema.getFactoryHostNode().newPKey();
		pkey.setRequiredHostNodeId( schema.nextHostNodeIdGen() );
		Buff.setRequiredHostNodeId( pkey.getRequiredHostNodeId() );
		CFSecBuffHostNodeByClusterIdxKey keyClusterIdx = schema.getFactoryHostNode().newClusterIdxKey();
		keyClusterIdx.setRequiredClusterId( Buff.getRequiredClusterId() );

		CFSecBuffHostNodeByUDescrIdxKey keyUDescrIdx = schema.getFactoryHostNode().newUDescrIdxKey();
		keyUDescrIdx.setRequiredClusterId( Buff.getRequiredClusterId() );
		keyUDescrIdx.setRequiredDescription( Buff.getRequiredDescription() );

		CFSecBuffHostNodeByHostNameIdxKey keyHostNameIdx = schema.getFactoryHostNode().newHostNameIdxKey();
		keyHostNameIdx.setRequiredClusterId( Buff.getRequiredClusterId() );
		keyHostNameIdx.setRequiredHostName( Buff.getRequiredHostName() );

		// Validate unique indexes

		if( dictByPKey.containsKey( pkey ) ) {
			throw new CFLibPrimaryKeyNotNewException( getClass(), S_ProcName, pkey );
		}

		if( dictByUDescrIdx.containsKey( keyUDescrIdx ) ) {
			throw new CFLibUniqueIndexViolationException( getClass(),
				S_ProcName,
				"HostNodeUDescrIdx",
				keyUDescrIdx );
		}

		if( dictByHostNameIdx.containsKey( keyHostNameIdx ) ) {
			throw new CFLibUniqueIndexViolationException( getClass(),
				S_ProcName,
				"HostNodeUHostNameIdx",
				keyHostNameIdx );
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
						"HostNodeCluster",
						"Cluster",
						null );
				}
			}
		}

		// Proceed with adding the new record

		dictByPKey.put( pkey, Buff );

		Map< CFLibDbKeyHash256, CFSecBuffHostNode > subdictClusterIdx;
		if( dictByClusterIdx.containsKey( keyClusterIdx ) ) {
			subdictClusterIdx = dictByClusterIdx.get( keyClusterIdx );
		}
		else {
			subdictClusterIdx = new HashMap< CFLibDbKeyHash256, CFSecBuffHostNode >();
			dictByClusterIdx.put( keyClusterIdx, subdictClusterIdx );
		}
		subdictClusterIdx.put( pkey, Buff );

		dictByUDescrIdx.put( keyUDescrIdx, Buff );

		dictByHostNameIdx.put( keyHostNameIdx, Buff );

	}

	public ICFSecHostNode readDerived( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 PKey )
	{
		final String S_ProcName = "CFSecRamHostNode.readDerived";
		ICFSecHostNode buff;
		if( dictByPKey.containsKey( PKey ) ) {
			buff = dictByPKey.get( PKey );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public ICFSecHostNode lockDerived( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 PKey )
	{
		final String S_ProcName = "CFSecRamHostNode.readDerived";
		CFLibDbKeyHash256 key = schema.getFactoryHostNode().newPKey();
		key.setRequiredHostNodeId( PKey.getRequiredHostNodeId() );
		ICFSecHostNode buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public ICFSecHostNode[] readAllDerived( ICFSecAuthorization Authorization ) {
		final String S_ProcName = "CFSecRamHostNode.readAllDerived";
		ICFSecHostNode[] retList = new ICFSecHostNode[ dictByPKey.values().size() ];
		Iterator< ICFSecHostNode > iter = dictByPKey.values().iterator();
		int idx = 0;
		while( iter.hasNext() ) {
			retList[ idx++ ] = iter.next();
		}
		return( retList );
	}

	public ICFSecHostNode[] readDerivedByClusterIdx( ICFSecAuthorization Authorization,
		long ClusterId )
	{
		final String S_ProcName = "CFSecRamHostNode.readDerivedByClusterIdx";
		CFSecBuffHostNodeByClusterIdxKey key = schema.getFactoryHostNode().newClusterIdxKey();
		key.setRequiredClusterId( ClusterId );

		ICFSecHostNode[] recArray;
		if( dictByClusterIdx.containsKey( key ) ) {
			Map< CFLibDbKeyHash256, CFSecBuffHostNode > subdictClusterIdx
				= dictByClusterIdx.get( key );
			recArray = new ICFSecHostNode[ subdictClusterIdx.size() ];
			Iterator< ICFSecHostNode > iter = subdictClusterIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFLibDbKeyHash256, CFSecBuffHostNode > subdictClusterIdx
				= new HashMap< CFLibDbKeyHash256, CFSecBuffHostNode >();
			dictByClusterIdx.put( key, subdictClusterIdx );
			recArray = new ICFSecHostNode[0];
		}
		return( recArray );
	}

	public ICFSecHostNode readDerivedByUDescrIdx( ICFSecAuthorization Authorization,
		long ClusterId,
		String Description )
	{
		final String S_ProcName = "CFSecRamHostNode.readDerivedByUDescrIdx";
		CFSecBuffHostNodeByUDescrIdxKey key = schema.getFactoryHostNode().newUDescrIdxKey();
		key.setRequiredClusterId( ClusterId );
		key.setRequiredDescription( Description );

		ICFSecHostNode buff;
		if( dictByUDescrIdx.containsKey( key ) ) {
			buff = dictByUDescrIdx.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public ICFSecHostNode readDerivedByHostNameIdx( ICFSecAuthorization Authorization,
		long ClusterId,
		String HostName )
	{
		final String S_ProcName = "CFSecRamHostNode.readDerivedByHostNameIdx";
		CFSecBuffHostNodeByHostNameIdxKey key = schema.getFactoryHostNode().newHostNameIdxKey();
		key.setRequiredClusterId( ClusterId );
		key.setRequiredHostName( HostName );

		ICFSecHostNode buff;
		if( dictByHostNameIdx.containsKey( key ) ) {
			buff = dictByHostNameIdx.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public ICFSecHostNode readDerivedByIdIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 HostNodeId )
	{
		final String S_ProcName = "CFSecRamHostNode.readDerivedByIdIdx() ";
		CFLibDbKeyHash256 key = schema.getFactoryHostNode().newPKey();
		key.setRequiredHostNodeId( HostNodeId );

		ICFSecHostNode buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public ICFSecHostNode readBuff( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 PKey )
	{
		final String S_ProcName = "CFSecRamHostNode.readBuff";
		ICFSecHostNode buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( ! buff.getClassCode().equals( "a002" ) ) ) {
			buff = null;
		}
		return( buff );
	}

	public ICFSecHostNode lockBuff( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 PKey )
	{
		final String S_ProcName = "lockBuff";
		ICFSecHostNode buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( ! buff.getClassCode().equals( "a002" ) ) ) {
			buff = null;
		}
		return( buff );
	}

	public ICFSecHostNode[] readAllBuff( ICFSecAuthorization Authorization )
	{
		final String S_ProcName = "CFSecRamHostNode.readAllBuff";
		ICFSecHostNode buff;
		ArrayList<ICFSecHostNode> filteredList = new ArrayList<ICFSecHostNode>();
		ICFSecHostNode[] buffList = readAllDerived( Authorization );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a002" ) ) {
				filteredList.add( buff );
			}
		}
		return( filteredList.toArray( new ICFSecHostNode[0] ) );
	}

	/**
	 *	Read a page of all the specific HostNode buffer instances.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@return All the specific HostNode instances in the database accessible for the Authorization.
	 */
	public ICFSecHostNode[] pageAllBuff( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 priorHostNodeId )
	{
		final String S_ProcName = "pageAllBuff";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	public ICFSecHostNode readBuffByIdIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 HostNodeId )
	{
		final String S_ProcName = "CFSecRamHostNode.readBuffByIdIdx() ";
		ICFSecHostNode buff = readDerivedByIdIdx( Authorization,
			HostNodeId );
		if( ( buff != null ) && buff.getClassCode().equals( "a002" ) ) {
			return( (ICFSecHostNode)buff );
		}
		else {
			return( null );
		}
	}

	public ICFSecHostNode[] readBuffByClusterIdx( ICFSecAuthorization Authorization,
		long ClusterId )
	{
		final String S_ProcName = "CFSecRamHostNode.readBuffByClusterIdx() ";
		ICFSecHostNode buff;
		ArrayList<ICFSecHostNode> filteredList = new ArrayList<ICFSecHostNode>();
		ICFSecHostNode[] buffList = readDerivedByClusterIdx( Authorization,
			ClusterId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a002" ) ) {
				filteredList.add( (ICFSecHostNode)buff );
			}
		}
		return( filteredList.toArray( new ICFSecHostNode[0] ) );
	}

	public ICFSecHostNode readBuffByUDescrIdx( ICFSecAuthorization Authorization,
		long ClusterId,
		String Description )
	{
		final String S_ProcName = "CFSecRamHostNode.readBuffByUDescrIdx() ";
		ICFSecHostNode buff = readDerivedByUDescrIdx( Authorization,
			ClusterId,
			Description );
		if( ( buff != null ) && buff.getClassCode().equals( "a002" ) ) {
			return( (ICFSecHostNode)buff );
		}
		else {
			return( null );
		}
	}

	public ICFSecHostNode readBuffByHostNameIdx( ICFSecAuthorization Authorization,
		long ClusterId,
		String HostName )
	{
		final String S_ProcName = "CFSecRamHostNode.readBuffByHostNameIdx() ";
		ICFSecHostNode buff = readDerivedByHostNameIdx( Authorization,
			ClusterId,
			HostName );
		if( ( buff != null ) && buff.getClassCode().equals( "a002" ) ) {
			return( (ICFSecHostNode)buff );
		}
		else {
			return( null );
		}
	}

	/**
	 *	Read a page array of the specific HostNode buffer instances identified by the duplicate key ClusterIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	ClusterId	The HostNode key attribute of the instance generating the id.
	 *
	 *	@return An array of derived buffer instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	public ICFSecHostNode[] pageBuffByClusterIdx( ICFSecAuthorization Authorization,
		long ClusterId,
		CFLibDbKeyHash256 priorHostNodeId )
	{
		final String S_ProcName = "pageBuffByClusterIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	public void updateHostNode( ICFSecAuthorization Authorization,
		ICFSecHostNode Buff )
	{
		CFLibDbKeyHash256 pkey = schema.getFactoryHostNode().newPKey();
		pkey.setRequiredHostNodeId( Buff.getRequiredHostNodeId() );
		ICFSecHostNode existing = dictByPKey.get( pkey );
		if( existing == null ) {
			throw new CFLibStaleCacheDetectedException( getClass(),
				"updateHostNode",
				"Existing record not found",
				"HostNode",
				pkey );
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() ) {
			throw new CFLibCollisionDetectedException( getClass(),
				"updateHostNode",
				pkey );
		}
		Buff.setRequiredRevision( Buff.getRequiredRevision() + 1 );
		CFSecBuffHostNodeByClusterIdxKey existingKeyClusterIdx = schema.getFactoryHostNode().newClusterIdxKey();
		existingKeyClusterIdx.setRequiredClusterId( existing.getRequiredClusterId() );

		CFSecBuffHostNodeByClusterIdxKey newKeyClusterIdx = schema.getFactoryHostNode().newClusterIdxKey();
		newKeyClusterIdx.setRequiredClusterId( Buff.getRequiredClusterId() );

		CFSecBuffHostNodeByUDescrIdxKey existingKeyUDescrIdx = schema.getFactoryHostNode().newUDescrIdxKey();
		existingKeyUDescrIdx.setRequiredClusterId( existing.getRequiredClusterId() );
		existingKeyUDescrIdx.setRequiredDescription( existing.getRequiredDescription() );

		CFSecBuffHostNodeByUDescrIdxKey newKeyUDescrIdx = schema.getFactoryHostNode().newUDescrIdxKey();
		newKeyUDescrIdx.setRequiredClusterId( Buff.getRequiredClusterId() );
		newKeyUDescrIdx.setRequiredDescription( Buff.getRequiredDescription() );

		CFSecBuffHostNodeByHostNameIdxKey existingKeyHostNameIdx = schema.getFactoryHostNode().newHostNameIdxKey();
		existingKeyHostNameIdx.setRequiredClusterId( existing.getRequiredClusterId() );
		existingKeyHostNameIdx.setRequiredHostName( existing.getRequiredHostName() );

		CFSecBuffHostNodeByHostNameIdxKey newKeyHostNameIdx = schema.getFactoryHostNode().newHostNameIdxKey();
		newKeyHostNameIdx.setRequiredClusterId( Buff.getRequiredClusterId() );
		newKeyHostNameIdx.setRequiredHostName( Buff.getRequiredHostName() );

		// Check unique indexes

		if( ! existingKeyUDescrIdx.equals( newKeyUDescrIdx ) ) {
			if( dictByUDescrIdx.containsKey( newKeyUDescrIdx ) ) {
				throw new CFLibUniqueIndexViolationException( getClass(),
					"updateHostNode",
					"HostNodeUDescrIdx",
					newKeyUDescrIdx );
			}
		}

		if( ! existingKeyHostNameIdx.equals( newKeyHostNameIdx ) ) {
			if( dictByHostNameIdx.containsKey( newKeyHostNameIdx ) ) {
				throw new CFLibUniqueIndexViolationException( getClass(),
					"updateHostNode",
					"HostNodeUHostNameIdx",
					newKeyHostNameIdx );
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
						"updateHostNode",
						"Container",
						"HostNodeCluster",
						"Cluster",
						null );
				}
			}
		}

		// Update is valid

		Map< CFLibDbKeyHash256, CFSecBuffHostNode > subdict;

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
			subdict = new HashMap< CFLibDbKeyHash256, CFSecBuffHostNode >();
			dictByClusterIdx.put( newKeyClusterIdx, subdict );
		}
		subdict.put( pkey, Buff );

		dictByUDescrIdx.remove( existingKeyUDescrIdx );
		dictByUDescrIdx.put( newKeyUDescrIdx, Buff );

		dictByHostNameIdx.remove( existingKeyHostNameIdx );
		dictByHostNameIdx.put( newKeyHostNameIdx, Buff );

	}

	public void deleteHostNode( ICFSecAuthorization Authorization,
		ICFSecHostNode Buff )
	{
		final String S_ProcName = "CFSecRamHostNodeTable.deleteHostNode() ";
		String classCode;
		CFLibDbKeyHash256 pkey = schema.getFactoryHostNode().newPKey();
		pkey.setRequiredHostNodeId( Buff.getRequiredHostNodeId() );
		ICFSecHostNode existing = dictByPKey.get( pkey );
		if( existing == null ) {
			return;
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() )
		{
			throw new CFLibCollisionDetectedException( getClass(),
				"deleteHostNode",
				pkey );
		}
					schema.getTableService().deleteServiceByHostIdx( Authorization,
						existing.getRequiredHostNodeId() );
		CFSecBuffHostNodeByClusterIdxKey keyClusterIdx = schema.getFactoryHostNode().newClusterIdxKey();
		keyClusterIdx.setRequiredClusterId( existing.getRequiredClusterId() );

		CFSecBuffHostNodeByUDescrIdxKey keyUDescrIdx = schema.getFactoryHostNode().newUDescrIdxKey();
		keyUDescrIdx.setRequiredClusterId( existing.getRequiredClusterId() );
		keyUDescrIdx.setRequiredDescription( existing.getRequiredDescription() );

		CFSecBuffHostNodeByHostNameIdxKey keyHostNameIdx = schema.getFactoryHostNode().newHostNameIdxKey();
		keyHostNameIdx.setRequiredClusterId( existing.getRequiredClusterId() );
		keyHostNameIdx.setRequiredHostName( existing.getRequiredHostName() );

		// Validate reverse foreign keys

		// Delete is valid
		Map< CFLibDbKeyHash256, CFSecBuffHostNode > subdict;

		dictByPKey.remove( pkey );

		subdict = dictByClusterIdx.get( keyClusterIdx );
		subdict.remove( pkey );

		dictByUDescrIdx.remove( keyUDescrIdx );

		dictByHostNameIdx.remove( keyHostNameIdx );

	}
	public void deleteHostNodeByIdIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argHostNodeId )
	{
		CFLibDbKeyHash256 key = schema.getFactoryHostNode().newPKey();
		key.setRequiredHostNodeId( argHostNodeId );
		deleteHostNodeByIdIdx( Authorization, key );
	}

	public void deleteHostNodeByIdIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argKey )
	{
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		ICFSecHostNode cur;
		LinkedList<ICFSecHostNode> matchSet = new LinkedList<ICFSecHostNode>();
		Iterator<ICFSecHostNode> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<ICFSecHostNode> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableHostNode().readDerivedByIdIdx( Authorization,
				cur.getRequiredHostNodeId() );
			deleteHostNode( Authorization, cur );
		}
	}

	public void deleteHostNodeByClusterIdx( ICFSecAuthorization Authorization,
		long argClusterId )
	{
		CFSecBuffHostNodeByClusterIdxKey key = schema.getFactoryHostNode().newClusterIdxKey();
		key.setRequiredClusterId( argClusterId );
		deleteHostNodeByClusterIdx( Authorization, key );
	}

	public void deleteHostNodeByClusterIdx( ICFSecAuthorization Authorization,
		ICFSecHostNodeByClusterIdxKey argKey )
	{
		ICFSecHostNode cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<ICFSecHostNode> matchSet = new LinkedList<ICFSecHostNode>();
		Iterator<ICFSecHostNode> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<ICFSecHostNode> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableHostNode().readDerivedByIdIdx( Authorization,
				cur.getRequiredHostNodeId() );
			deleteHostNode( Authorization, cur );
		}
	}

	public void deleteHostNodeByUDescrIdx( ICFSecAuthorization Authorization,
		long argClusterId,
		String argDescription )
	{
		CFSecBuffHostNodeByUDescrIdxKey key = schema.getFactoryHostNode().newUDescrIdxKey();
		key.setRequiredClusterId( argClusterId );
		key.setRequiredDescription( argDescription );
		deleteHostNodeByUDescrIdx( Authorization, key );
	}

	public void deleteHostNodeByUDescrIdx( ICFSecAuthorization Authorization,
		ICFSecHostNodeByUDescrIdxKey argKey )
	{
		ICFSecHostNode cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<ICFSecHostNode> matchSet = new LinkedList<ICFSecHostNode>();
		Iterator<ICFSecHostNode> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<ICFSecHostNode> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableHostNode().readDerivedByIdIdx( Authorization,
				cur.getRequiredHostNodeId() );
			deleteHostNode( Authorization, cur );
		}
	}

	public void deleteHostNodeByHostNameIdx( ICFSecAuthorization Authorization,
		long argClusterId,
		String argHostName )
	{
		CFSecBuffHostNodeByHostNameIdxKey key = schema.getFactoryHostNode().newHostNameIdxKey();
		key.setRequiredClusterId( argClusterId );
		key.setRequiredHostName( argHostName );
		deleteHostNodeByHostNameIdx( Authorization, key );
	}

	public void deleteHostNodeByHostNameIdx( ICFSecAuthorization Authorization,
		ICFSecHostNodeByHostNameIdxKey argKey )
	{
		ICFSecHostNode cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<ICFSecHostNode> matchSet = new LinkedList<ICFSecHostNode>();
		Iterator<ICFSecHostNode> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<ICFSecHostNode> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableHostNode().readDerivedByIdIdx( Authorization,
				cur.getRequiredHostNodeId() );
			deleteHostNode( Authorization, cur );
		}
	}
}
