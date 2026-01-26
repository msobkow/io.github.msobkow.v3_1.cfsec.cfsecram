
// Description: Java 25 in-memory RAM DbIO implementation for SysCluster.

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
 *	CFSecRamSysClusterTable in-memory RAM DbIO implementation
 *	for SysCluster.
 */
public class CFSecRamSysClusterTable
	implements ICFSecSysClusterTable
{
	private ICFSecSchema schema;
	private Map< Integer,
				CFSecBuffSysCluster > dictByPKey
		= new HashMap< Integer,
				CFSecBuffSysCluster >();
	private Map< CFSecBuffSysClusterByClusterIdxKey,
				Map< Integer,
					CFSecBuffSysCluster >> dictByClusterIdx
		= new HashMap< CFSecBuffSysClusterByClusterIdxKey,
				Map< Integer,
					CFSecBuffSysCluster >>();

	public CFSecRamSysClusterTable( ICFSecSchema argSchema ) {
		schema = argSchema;
	}

	public void createSysCluster( ICFSecAuthorization Authorization,
		ICFSecSysCluster Buff )
	{
		final String S_ProcName = "createSysCluster";
		Integer pkey = schema.getFactorySysCluster().newPKey();
		pkey.setRequiredSingletonId( Buff.getRequiredSingletonId() );
		Buff.setRequiredSingletonId( pkey.getRequiredSingletonId() );
		CFSecBuffSysClusterByClusterIdxKey keyClusterIdx = schema.getFactorySysCluster().newClusterIdxKey();
		keyClusterIdx.setRequiredClusterId( Buff.getRequiredClusterId() );

		// Validate unique indexes

		if( dictByPKey.containsKey( pkey ) ) {
			throw new CFLibPrimaryKeyNotNewException( getClass(), S_ProcName, pkey );
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
						"SysClusterCluster",
						"Cluster",
						null );
				}
			}
		}

		// Proceed with adding the new record

		dictByPKey.put( pkey, Buff );

		Map< Integer, CFSecBuffSysCluster > subdictClusterIdx;
		if( dictByClusterIdx.containsKey( keyClusterIdx ) ) {
			subdictClusterIdx = dictByClusterIdx.get( keyClusterIdx );
		}
		else {
			subdictClusterIdx = new HashMap< Integer, CFSecBuffSysCluster >();
			dictByClusterIdx.put( keyClusterIdx, subdictClusterIdx );
		}
		subdictClusterIdx.put( pkey, Buff );

	}

	public ICFSecSysCluster readDerived( ICFSecAuthorization Authorization,
		Integer PKey )
	{
		final String S_ProcName = "CFSecRamSysCluster.readDerived";
		ICFSecSysCluster buff;
		if( dictByPKey.containsKey( PKey ) ) {
			buff = dictByPKey.get( PKey );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public ICFSecSysCluster lockDerived( ICFSecAuthorization Authorization,
		Integer PKey )
	{
		final String S_ProcName = "CFSecRamSysCluster.readDerived";
		Integer key = schema.getFactorySysCluster().newPKey();
		key.setRequiredSingletonId( PKey.getRequiredSingletonId() );
		ICFSecSysCluster buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public ICFSecSysCluster[] readAllDerived( ICFSecAuthorization Authorization ) {
		final String S_ProcName = "CFSecRamSysCluster.readAllDerived";
		ICFSecSysCluster[] retList = new ICFSecSysCluster[ dictByPKey.values().size() ];
		Iterator< ICFSecSysCluster > iter = dictByPKey.values().iterator();
		int idx = 0;
		while( iter.hasNext() ) {
			retList[ idx++ ] = iter.next();
		}
		return( retList );
	}

	public ICFSecSysCluster[] readDerivedByClusterIdx( ICFSecAuthorization Authorization,
		long ClusterId )
	{
		final String S_ProcName = "CFSecRamSysCluster.readDerivedByClusterIdx";
		CFSecBuffSysClusterByClusterIdxKey key = schema.getFactorySysCluster().newClusterIdxKey();
		key.setRequiredClusterId( ClusterId );

		ICFSecSysCluster[] recArray;
		if( dictByClusterIdx.containsKey( key ) ) {
			Map< Integer, CFSecBuffSysCluster > subdictClusterIdx
				= dictByClusterIdx.get( key );
			recArray = new ICFSecSysCluster[ subdictClusterIdx.size() ];
			Iterator< ICFSecSysCluster > iter = subdictClusterIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< Integer, CFSecBuffSysCluster > subdictClusterIdx
				= new HashMap< Integer, CFSecBuffSysCluster >();
			dictByClusterIdx.put( key, subdictClusterIdx );
			recArray = new ICFSecSysCluster[0];
		}
		return( recArray );
	}

	public ICFSecSysCluster readDerivedByIdIdx( ICFSecAuthorization Authorization,
		int SingletonId )
	{
		final String S_ProcName = "CFSecRamSysCluster.readDerivedByIdIdx() ";
		Integer key = schema.getFactorySysCluster().newPKey();
		key.setRequiredSingletonId( SingletonId );

		ICFSecSysCluster buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public ICFSecSysCluster readBuff( ICFSecAuthorization Authorization,
		Integer PKey )
	{
		final String S_ProcName = "CFSecRamSysCluster.readBuff";
		ICFSecSysCluster buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( ! buff.getClassCode().equals( "a014" ) ) ) {
			buff = null;
		}
		return( buff );
	}

	public ICFSecSysCluster lockBuff( ICFSecAuthorization Authorization,
		Integer PKey )
	{
		final String S_ProcName = "lockBuff";
		ICFSecSysCluster buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( ! buff.getClassCode().equals( "a014" ) ) ) {
			buff = null;
		}
		return( buff );
	}

	public ICFSecSysCluster[] readAllBuff( ICFSecAuthorization Authorization )
	{
		final String S_ProcName = "CFSecRamSysCluster.readAllBuff";
		ICFSecSysCluster buff;
		ArrayList<ICFSecSysCluster> filteredList = new ArrayList<ICFSecSysCluster>();
		ICFSecSysCluster[] buffList = readAllDerived( Authorization );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a014" ) ) {
				filteredList.add( buff );
			}
		}
		return( filteredList.toArray( new ICFSecSysCluster[0] ) );
	}

	public ICFSecSysCluster readBuffByIdIdx( ICFSecAuthorization Authorization,
		int SingletonId )
	{
		final String S_ProcName = "CFSecRamSysCluster.readBuffByIdIdx() ";
		ICFSecSysCluster buff = readDerivedByIdIdx( Authorization,
			SingletonId );
		if( ( buff != null ) && buff.getClassCode().equals( "a014" ) ) {
			return( (ICFSecSysCluster)buff );
		}
		else {
			return( null );
		}
	}

	public ICFSecSysCluster[] readBuffByClusterIdx( ICFSecAuthorization Authorization,
		long ClusterId )
	{
		final String S_ProcName = "CFSecRamSysCluster.readBuffByClusterIdx() ";
		ICFSecSysCluster buff;
		ArrayList<ICFSecSysCluster> filteredList = new ArrayList<ICFSecSysCluster>();
		ICFSecSysCluster[] buffList = readDerivedByClusterIdx( Authorization,
			ClusterId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a014" ) ) {
				filteredList.add( (ICFSecSysCluster)buff );
			}
		}
		return( filteredList.toArray( new ICFSecSysCluster[0] ) );
	}

	public void updateSysCluster( ICFSecAuthorization Authorization,
		ICFSecSysCluster Buff )
	{
		Integer pkey = schema.getFactorySysCluster().newPKey();
		pkey.setRequiredSingletonId( Buff.getRequiredSingletonId() );
		ICFSecSysCluster existing = dictByPKey.get( pkey );
		if( existing == null ) {
			throw new CFLibStaleCacheDetectedException( getClass(),
				"updateSysCluster",
				"Existing record not found",
				"SysCluster",
				pkey );
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() ) {
			throw new CFLibCollisionDetectedException( getClass(),
				"updateSysCluster",
				pkey );
		}
		Buff.setRequiredRevision( Buff.getRequiredRevision() + 1 );
		CFSecBuffSysClusterByClusterIdxKey existingKeyClusterIdx = schema.getFactorySysCluster().newClusterIdxKey();
		existingKeyClusterIdx.setRequiredClusterId( existing.getRequiredClusterId() );

		CFSecBuffSysClusterByClusterIdxKey newKeyClusterIdx = schema.getFactorySysCluster().newClusterIdxKey();
		newKeyClusterIdx.setRequiredClusterId( Buff.getRequiredClusterId() );

		// Check unique indexes

		// Validate foreign keys

		{
			boolean allNull = true;

			if( allNull ) {
				if( null == schema.getTableCluster().readDerivedByIdIdx( Authorization,
						Buff.getRequiredClusterId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						"updateSysCluster",
						"Container",
						"SysClusterCluster",
						"Cluster",
						null );
				}
			}
		}

		// Update is valid

		Map< Integer, CFSecBuffSysCluster > subdict;

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
			subdict = new HashMap< Integer, CFSecBuffSysCluster >();
			dictByClusterIdx.put( newKeyClusterIdx, subdict );
		}
		subdict.put( pkey, Buff );

	}

	public void deleteSysCluster( ICFSecAuthorization Authorization,
		ICFSecSysCluster Buff )
	{
		final String S_ProcName = "CFSecRamSysClusterTable.deleteSysCluster() ";
		String classCode;
		Integer pkey = schema.getFactorySysCluster().newPKey();
		pkey.setRequiredSingletonId( Buff.getRequiredSingletonId() );
		ICFSecSysCluster existing = dictByPKey.get( pkey );
		if( existing == null ) {
			return;
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() )
		{
			throw new CFLibCollisionDetectedException( getClass(),
				"deleteSysCluster",
				pkey );
		}
		CFSecBuffSysClusterByClusterIdxKey keyClusterIdx = schema.getFactorySysCluster().newClusterIdxKey();
		keyClusterIdx.setRequiredClusterId( existing.getRequiredClusterId() );

		// Validate reverse foreign keys

		// Delete is valid
		Map< Integer, CFSecBuffSysCluster > subdict;

		dictByPKey.remove( pkey );

		subdict = dictByClusterIdx.get( keyClusterIdx );
		subdict.remove( pkey );

	}
	public void deleteSysClusterByIdIdx( ICFSecAuthorization Authorization,
		int argSingletonId )
	{
		Integer key = schema.getFactorySysCluster().newPKey();
		key.setRequiredSingletonId( argSingletonId );
		deleteSysClusterByIdIdx( Authorization, key );
	}

	public void deleteSysClusterByIdIdx( ICFSecAuthorization Authorization,
		Integer argKey )
	{
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		ICFSecSysCluster cur;
		LinkedList<ICFSecSysCluster> matchSet = new LinkedList<ICFSecSysCluster>();
		Iterator<ICFSecSysCluster> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<ICFSecSysCluster> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableSysCluster().readDerivedByIdIdx( Authorization,
				cur.getRequiredSingletonId() );
			deleteSysCluster( Authorization, cur );
		}
	}

	public void deleteSysClusterByClusterIdx( ICFSecAuthorization Authorization,
		long argClusterId )
	{
		CFSecBuffSysClusterByClusterIdxKey key = schema.getFactorySysCluster().newClusterIdxKey();
		key.setRequiredClusterId( argClusterId );
		deleteSysClusterByClusterIdx( Authorization, key );
	}

	public void deleteSysClusterByClusterIdx( ICFSecAuthorization Authorization,
		ICFSecSysClusterByClusterIdxKey argKey )
	{
		ICFSecSysCluster cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<ICFSecSysCluster> matchSet = new LinkedList<ICFSecSysCluster>();
		Iterator<ICFSecSysCluster> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<ICFSecSysCluster> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableSysCluster().readDerivedByIdIdx( Authorization,
				cur.getRequiredSingletonId() );
			deleteSysCluster( Authorization, cur );
		}
	}
}
