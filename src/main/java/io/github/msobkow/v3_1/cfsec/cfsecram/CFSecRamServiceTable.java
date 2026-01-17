
// Description: Java 25 in-memory RAM DbIO implementation for Service.

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
 *	CFSecRamServiceTable in-memory RAM DbIO implementation
 *	for Service.
 */
public class CFSecRamServiceTable
	implements ICFSecServiceTable
{
	private ICFSecSchema schema;
	private Map< CFSecServicePKey,
				CFSecServiceBuff > dictByPKey
		= new HashMap< CFSecServicePKey,
				CFSecServiceBuff >();
	private Map< CFSecServiceByClusterIdxKey,
				Map< CFSecServicePKey,
					CFSecServiceBuff >> dictByClusterIdx
		= new HashMap< CFSecServiceByClusterIdxKey,
				Map< CFSecServicePKey,
					CFSecServiceBuff >>();
	private Map< CFSecServiceByHostIdxKey,
				Map< CFSecServicePKey,
					CFSecServiceBuff >> dictByHostIdx
		= new HashMap< CFSecServiceByHostIdxKey,
				Map< CFSecServicePKey,
					CFSecServiceBuff >>();
	private Map< CFSecServiceByTypeIdxKey,
				Map< CFSecServicePKey,
					CFSecServiceBuff >> dictByTypeIdx
		= new HashMap< CFSecServiceByTypeIdxKey,
				Map< CFSecServicePKey,
					CFSecServiceBuff >>();
	private Map< CFSecServiceByUTypeIdxKey,
			CFSecServiceBuff > dictByUTypeIdx
		= new HashMap< CFSecServiceByUTypeIdxKey,
			CFSecServiceBuff >();
	private Map< CFSecServiceByUHostPortIdxKey,
			CFSecServiceBuff > dictByUHostPortIdx
		= new HashMap< CFSecServiceByUHostPortIdxKey,
			CFSecServiceBuff >();

	public CFSecRamServiceTable( ICFSecSchema argSchema ) {
		schema = argSchema;
	}

	public void createService( CFSecAuthorization Authorization,
		CFSecServiceBuff Buff )
	{
		final String S_ProcName = "createService";
		CFSecServicePKey pkey = schema.getFactoryService().newPKey();
		pkey.setRequiredServiceId( schema.nextServiceIdGen() );
		Buff.setRequiredServiceId( pkey.getRequiredServiceId() );
		CFSecServiceByClusterIdxKey keyClusterIdx = schema.getFactoryService().newClusterIdxKey();
		keyClusterIdx.setRequiredClusterId( Buff.getRequiredClusterId() );

		CFSecServiceByHostIdxKey keyHostIdx = schema.getFactoryService().newHostIdxKey();
		keyHostIdx.setRequiredHostNodeId( Buff.getRequiredHostNodeId() );

		CFSecServiceByTypeIdxKey keyTypeIdx = schema.getFactoryService().newTypeIdxKey();
		keyTypeIdx.setRequiredServiceTypeId( Buff.getRequiredServiceTypeId() );

		CFSecServiceByUTypeIdxKey keyUTypeIdx = schema.getFactoryService().newUTypeIdxKey();
		keyUTypeIdx.setRequiredClusterId( Buff.getRequiredClusterId() );
		keyUTypeIdx.setRequiredHostNodeId( Buff.getRequiredHostNodeId() );
		keyUTypeIdx.setRequiredServiceTypeId( Buff.getRequiredServiceTypeId() );

		CFSecServiceByUHostPortIdxKey keyUHostPortIdx = schema.getFactoryService().newUHostPortIdxKey();
		keyUHostPortIdx.setRequiredClusterId( Buff.getRequiredClusterId() );
		keyUHostPortIdx.setRequiredHostNodeId( Buff.getRequiredHostNodeId() );
		keyUHostPortIdx.setRequiredHostPort( Buff.getRequiredHostPort() );

		// Validate unique indexes

		if( dictByPKey.containsKey( pkey ) ) {
			throw new CFLibPrimaryKeyNotNewException( getClass(), S_ProcName, pkey );
		}

		if( dictByUTypeIdx.containsKey( keyUTypeIdx ) ) {
			throw new CFLibUniqueIndexViolationException( getClass(),
				S_ProcName,
				"ServiceUTypeIdx",
				keyUTypeIdx );
		}

		if( dictByUHostPortIdx.containsKey( keyUHostPortIdx ) ) {
			throw new CFLibUniqueIndexViolationException( getClass(),
				S_ProcName,
				"ServiceUHostPort",
				keyUHostPortIdx );
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
						"ServiceCluster",
						"Cluster",
						null );
				}
			}
		}

		// Proceed with adding the new record

		dictByPKey.put( pkey, Buff );

		Map< CFSecServicePKey, CFSecServiceBuff > subdictClusterIdx;
		if( dictByClusterIdx.containsKey( keyClusterIdx ) ) {
			subdictClusterIdx = dictByClusterIdx.get( keyClusterIdx );
		}
		else {
			subdictClusterIdx = new HashMap< CFSecServicePKey, CFSecServiceBuff >();
			dictByClusterIdx.put( keyClusterIdx, subdictClusterIdx );
		}
		subdictClusterIdx.put( pkey, Buff );

		Map< CFSecServicePKey, CFSecServiceBuff > subdictHostIdx;
		if( dictByHostIdx.containsKey( keyHostIdx ) ) {
			subdictHostIdx = dictByHostIdx.get( keyHostIdx );
		}
		else {
			subdictHostIdx = new HashMap< CFSecServicePKey, CFSecServiceBuff >();
			dictByHostIdx.put( keyHostIdx, subdictHostIdx );
		}
		subdictHostIdx.put( pkey, Buff );

		Map< CFSecServicePKey, CFSecServiceBuff > subdictTypeIdx;
		if( dictByTypeIdx.containsKey( keyTypeIdx ) ) {
			subdictTypeIdx = dictByTypeIdx.get( keyTypeIdx );
		}
		else {
			subdictTypeIdx = new HashMap< CFSecServicePKey, CFSecServiceBuff >();
			dictByTypeIdx.put( keyTypeIdx, subdictTypeIdx );
		}
		subdictTypeIdx.put( pkey, Buff );

		dictByUTypeIdx.put( keyUTypeIdx, Buff );

		dictByUHostPortIdx.put( keyUHostPortIdx, Buff );

	}

	public CFSecServiceBuff readDerived( CFSecAuthorization Authorization,
		CFSecServicePKey PKey )
	{
		final String S_ProcName = "CFSecRamService.readDerived";
		CFSecServicePKey key = schema.getFactoryService().newPKey();
		key.setRequiredServiceId( PKey.getRequiredServiceId() );
		CFSecServiceBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecServiceBuff lockDerived( CFSecAuthorization Authorization,
		CFSecServicePKey PKey )
	{
		final String S_ProcName = "CFSecRamService.readDerived";
		CFSecServicePKey key = schema.getFactoryService().newPKey();
		key.setRequiredServiceId( PKey.getRequiredServiceId() );
		CFSecServiceBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecServiceBuff[] readAllDerived( CFSecAuthorization Authorization ) {
		final String S_ProcName = "CFSecRamService.readAllDerived";
		CFSecServiceBuff[] retList = new CFSecServiceBuff[ dictByPKey.values().size() ];
		Iterator< CFSecServiceBuff > iter = dictByPKey.values().iterator();
		int idx = 0;
		while( iter.hasNext() ) {
			retList[ idx++ ] = iter.next();
		}
		return( retList );
	}

	public CFSecServiceBuff[] readDerivedByClusterIdx( CFSecAuthorization Authorization,
		long ClusterId )
	{
		final String S_ProcName = "CFSecRamService.readDerivedByClusterIdx";
		CFSecServiceByClusterIdxKey key = schema.getFactoryService().newClusterIdxKey();
		key.setRequiredClusterId( ClusterId );

		CFSecServiceBuff[] recArray;
		if( dictByClusterIdx.containsKey( key ) ) {
			Map< CFSecServicePKey, CFSecServiceBuff > subdictClusterIdx
				= dictByClusterIdx.get( key );
			recArray = new CFSecServiceBuff[ subdictClusterIdx.size() ];
			Iterator< CFSecServiceBuff > iter = subdictClusterIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFSecServicePKey, CFSecServiceBuff > subdictClusterIdx
				= new HashMap< CFSecServicePKey, CFSecServiceBuff >();
			dictByClusterIdx.put( key, subdictClusterIdx );
			recArray = new CFSecServiceBuff[0];
		}
		return( recArray );
	}

	public CFSecServiceBuff[] readDerivedByHostIdx( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 HostNodeId )
	{
		final String S_ProcName = "CFSecRamService.readDerivedByHostIdx";
		CFSecServiceByHostIdxKey key = schema.getFactoryService().newHostIdxKey();
		key.setRequiredHostNodeId( HostNodeId );

		CFSecServiceBuff[] recArray;
		if( dictByHostIdx.containsKey( key ) ) {
			Map< CFSecServicePKey, CFSecServiceBuff > subdictHostIdx
				= dictByHostIdx.get( key );
			recArray = new CFSecServiceBuff[ subdictHostIdx.size() ];
			Iterator< CFSecServiceBuff > iter = subdictHostIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFSecServicePKey, CFSecServiceBuff > subdictHostIdx
				= new HashMap< CFSecServicePKey, CFSecServiceBuff >();
			dictByHostIdx.put( key, subdictHostIdx );
			recArray = new CFSecServiceBuff[0];
		}
		return( recArray );
	}

	public CFSecServiceBuff[] readDerivedByTypeIdx( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 ServiceTypeId )
	{
		final String S_ProcName = "CFSecRamService.readDerivedByTypeIdx";
		CFSecServiceByTypeIdxKey key = schema.getFactoryService().newTypeIdxKey();
		key.setRequiredServiceTypeId( ServiceTypeId );

		CFSecServiceBuff[] recArray;
		if( dictByTypeIdx.containsKey( key ) ) {
			Map< CFSecServicePKey, CFSecServiceBuff > subdictTypeIdx
				= dictByTypeIdx.get( key );
			recArray = new CFSecServiceBuff[ subdictTypeIdx.size() ];
			Iterator< CFSecServiceBuff > iter = subdictTypeIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFSecServicePKey, CFSecServiceBuff > subdictTypeIdx
				= new HashMap< CFSecServicePKey, CFSecServiceBuff >();
			dictByTypeIdx.put( key, subdictTypeIdx );
			recArray = new CFSecServiceBuff[0];
		}
		return( recArray );
	}

	public CFSecServiceBuff readDerivedByUTypeIdx( CFSecAuthorization Authorization,
		long ClusterId,
		CFLibDbKeyHash256 HostNodeId,
		CFLibDbKeyHash256 ServiceTypeId )
	{
		final String S_ProcName = "CFSecRamService.readDerivedByUTypeIdx";
		CFSecServiceByUTypeIdxKey key = schema.getFactoryService().newUTypeIdxKey();
		key.setRequiredClusterId( ClusterId );
		key.setRequiredHostNodeId( HostNodeId );
		key.setRequiredServiceTypeId( ServiceTypeId );

		CFSecServiceBuff buff;
		if( dictByUTypeIdx.containsKey( key ) ) {
			buff = dictByUTypeIdx.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecServiceBuff readDerivedByUHostPortIdx( CFSecAuthorization Authorization,
		long ClusterId,
		CFLibDbKeyHash256 HostNodeId,
		short HostPort )
	{
		final String S_ProcName = "CFSecRamService.readDerivedByUHostPortIdx";
		CFSecServiceByUHostPortIdxKey key = schema.getFactoryService().newUHostPortIdxKey();
		key.setRequiredClusterId( ClusterId );
		key.setRequiredHostNodeId( HostNodeId );
		key.setRequiredHostPort( HostPort );

		CFSecServiceBuff buff;
		if( dictByUHostPortIdx.containsKey( key ) ) {
			buff = dictByUHostPortIdx.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecServiceBuff readDerivedByIdIdx( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 ServiceId )
	{
		final String S_ProcName = "CFSecRamService.readDerivedByIdIdx() ";
		CFSecServicePKey key = schema.getFactoryService().newPKey();
		key.setRequiredServiceId( ServiceId );

		CFSecServiceBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecServiceBuff readBuff( CFSecAuthorization Authorization,
		CFSecServicePKey PKey )
	{
		final String S_ProcName = "CFSecRamService.readBuff";
		CFSecServiceBuff buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( ! buff.getClassCode().equals( "a012" ) ) ) {
			buff = null;
		}
		return( buff );
	}

	public CFSecServiceBuff lockBuff( CFSecAuthorization Authorization,
		CFSecServicePKey PKey )
	{
		final String S_ProcName = "lockBuff";
		CFSecServiceBuff buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( ! buff.getClassCode().equals( "a012" ) ) ) {
			buff = null;
		}
		return( buff );
	}

	public CFSecServiceBuff[] readAllBuff( CFSecAuthorization Authorization )
	{
		final String S_ProcName = "CFSecRamService.readAllBuff";
		CFSecServiceBuff buff;
		ArrayList<CFSecServiceBuff> filteredList = new ArrayList<CFSecServiceBuff>();
		CFSecServiceBuff[] buffList = readAllDerived( Authorization );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a012" ) ) {
				filteredList.add( buff );
			}
		}
		return( filteredList.toArray( new CFSecServiceBuff[0] ) );
	}

	/**
	 *	Read a page of all the specific Service buffer instances.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@return All the specific Service instances in the database accessible for the Authorization.
	 */
	public CFSecServiceBuff[] pageAllBuff( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 priorServiceId )
	{
		final String S_ProcName = "pageAllBuff";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	public CFSecServiceBuff readBuffByIdIdx( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 ServiceId )
	{
		final String S_ProcName = "CFSecRamService.readBuffByIdIdx() ";
		CFSecServiceBuff buff = readDerivedByIdIdx( Authorization,
			ServiceId );
		if( ( buff != null ) && buff.getClassCode().equals( "a012" ) ) {
			return( (CFSecServiceBuff)buff );
		}
		else {
			return( null );
		}
	}

	public CFSecServiceBuff[] readBuffByClusterIdx( CFSecAuthorization Authorization,
		long ClusterId )
	{
		final String S_ProcName = "CFSecRamService.readBuffByClusterIdx() ";
		CFSecServiceBuff buff;
		ArrayList<CFSecServiceBuff> filteredList = new ArrayList<CFSecServiceBuff>();
		CFSecServiceBuff[] buffList = readDerivedByClusterIdx( Authorization,
			ClusterId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a012" ) ) {
				filteredList.add( (CFSecServiceBuff)buff );
			}
		}
		return( filteredList.toArray( new CFSecServiceBuff[0] ) );
	}

	public CFSecServiceBuff[] readBuffByHostIdx( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 HostNodeId )
	{
		final String S_ProcName = "CFSecRamService.readBuffByHostIdx() ";
		CFSecServiceBuff buff;
		ArrayList<CFSecServiceBuff> filteredList = new ArrayList<CFSecServiceBuff>();
		CFSecServiceBuff[] buffList = readDerivedByHostIdx( Authorization,
			HostNodeId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a012" ) ) {
				filteredList.add( (CFSecServiceBuff)buff );
			}
		}
		return( filteredList.toArray( new CFSecServiceBuff[0] ) );
	}

	public CFSecServiceBuff[] readBuffByTypeIdx( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 ServiceTypeId )
	{
		final String S_ProcName = "CFSecRamService.readBuffByTypeIdx() ";
		CFSecServiceBuff buff;
		ArrayList<CFSecServiceBuff> filteredList = new ArrayList<CFSecServiceBuff>();
		CFSecServiceBuff[] buffList = readDerivedByTypeIdx( Authorization,
			ServiceTypeId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a012" ) ) {
				filteredList.add( (CFSecServiceBuff)buff );
			}
		}
		return( filteredList.toArray( new CFSecServiceBuff[0] ) );
	}

	public CFSecServiceBuff readBuffByUTypeIdx( CFSecAuthorization Authorization,
		long ClusterId,
		CFLibDbKeyHash256 HostNodeId,
		CFLibDbKeyHash256 ServiceTypeId )
	{
		final String S_ProcName = "CFSecRamService.readBuffByUTypeIdx() ";
		CFSecServiceBuff buff = readDerivedByUTypeIdx( Authorization,
			ClusterId,
			HostNodeId,
			ServiceTypeId );
		if( ( buff != null ) && buff.getClassCode().equals( "a012" ) ) {
			return( (CFSecServiceBuff)buff );
		}
		else {
			return( null );
		}
	}

	public CFSecServiceBuff readBuffByUHostPortIdx( CFSecAuthorization Authorization,
		long ClusterId,
		CFLibDbKeyHash256 HostNodeId,
		short HostPort )
	{
		final String S_ProcName = "CFSecRamService.readBuffByUHostPortIdx() ";
		CFSecServiceBuff buff = readDerivedByUHostPortIdx( Authorization,
			ClusterId,
			HostNodeId,
			HostPort );
		if( ( buff != null ) && buff.getClassCode().equals( "a012" ) ) {
			return( (CFSecServiceBuff)buff );
		}
		else {
			return( null );
		}
	}

	/**
	 *	Read a page array of the specific Service buffer instances identified by the duplicate key ClusterIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	ClusterId	The Service key attribute of the instance generating the id.
	 *
	 *	@return An array of derived buffer instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	public CFSecServiceBuff[] pageBuffByClusterIdx( CFSecAuthorization Authorization,
		long ClusterId,
		CFLibDbKeyHash256 priorServiceId )
	{
		final String S_ProcName = "pageBuffByClusterIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	/**
	 *	Read a page array of the specific Service buffer instances identified by the duplicate key HostIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	HostNodeId	The Service key attribute of the instance generating the id.
	 *
	 *	@return An array of derived buffer instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	public CFSecServiceBuff[] pageBuffByHostIdx( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 HostNodeId,
		CFLibDbKeyHash256 priorServiceId )
	{
		final String S_ProcName = "pageBuffByHostIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	/**
	 *	Read a page array of the specific Service buffer instances identified by the duplicate key TypeIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	ServiceTypeId	The Service key attribute of the instance generating the id.
	 *
	 *	@return An array of derived buffer instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	public CFSecServiceBuff[] pageBuffByTypeIdx( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 ServiceTypeId,
		CFLibDbKeyHash256 priorServiceId )
	{
		final String S_ProcName = "pageBuffByTypeIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	public void updateService( CFSecAuthorization Authorization,
		CFSecServiceBuff Buff )
	{
		CFSecServicePKey pkey = schema.getFactoryService().newPKey();
		pkey.setRequiredServiceId( Buff.getRequiredServiceId() );
		CFSecServiceBuff existing = dictByPKey.get( pkey );
		if( existing == null ) {
			throw new CFLibStaleCacheDetectedException( getClass(),
				"updateService",
				"Existing record not found",
				"Service",
				pkey );
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() ) {
			throw new CFLibCollisionDetectedException( getClass(),
				"updateService",
				pkey );
		}
		Buff.setRequiredRevision( Buff.getRequiredRevision() + 1 );
		CFSecServiceByClusterIdxKey existingKeyClusterIdx = schema.getFactoryService().newClusterIdxKey();
		existingKeyClusterIdx.setRequiredClusterId( existing.getRequiredClusterId() );

		CFSecServiceByClusterIdxKey newKeyClusterIdx = schema.getFactoryService().newClusterIdxKey();
		newKeyClusterIdx.setRequiredClusterId( Buff.getRequiredClusterId() );

		CFSecServiceByHostIdxKey existingKeyHostIdx = schema.getFactoryService().newHostIdxKey();
		existingKeyHostIdx.setRequiredHostNodeId( existing.getRequiredHostNodeId() );

		CFSecServiceByHostIdxKey newKeyHostIdx = schema.getFactoryService().newHostIdxKey();
		newKeyHostIdx.setRequiredHostNodeId( Buff.getRequiredHostNodeId() );

		CFSecServiceByTypeIdxKey existingKeyTypeIdx = schema.getFactoryService().newTypeIdxKey();
		existingKeyTypeIdx.setRequiredServiceTypeId( existing.getRequiredServiceTypeId() );

		CFSecServiceByTypeIdxKey newKeyTypeIdx = schema.getFactoryService().newTypeIdxKey();
		newKeyTypeIdx.setRequiredServiceTypeId( Buff.getRequiredServiceTypeId() );

		CFSecServiceByUTypeIdxKey existingKeyUTypeIdx = schema.getFactoryService().newUTypeIdxKey();
		existingKeyUTypeIdx.setRequiredClusterId( existing.getRequiredClusterId() );
		existingKeyUTypeIdx.setRequiredHostNodeId( existing.getRequiredHostNodeId() );
		existingKeyUTypeIdx.setRequiredServiceTypeId( existing.getRequiredServiceTypeId() );

		CFSecServiceByUTypeIdxKey newKeyUTypeIdx = schema.getFactoryService().newUTypeIdxKey();
		newKeyUTypeIdx.setRequiredClusterId( Buff.getRequiredClusterId() );
		newKeyUTypeIdx.setRequiredHostNodeId( Buff.getRequiredHostNodeId() );
		newKeyUTypeIdx.setRequiredServiceTypeId( Buff.getRequiredServiceTypeId() );

		CFSecServiceByUHostPortIdxKey existingKeyUHostPortIdx = schema.getFactoryService().newUHostPortIdxKey();
		existingKeyUHostPortIdx.setRequiredClusterId( existing.getRequiredClusterId() );
		existingKeyUHostPortIdx.setRequiredHostNodeId( existing.getRequiredHostNodeId() );
		existingKeyUHostPortIdx.setRequiredHostPort( existing.getRequiredHostPort() );

		CFSecServiceByUHostPortIdxKey newKeyUHostPortIdx = schema.getFactoryService().newUHostPortIdxKey();
		newKeyUHostPortIdx.setRequiredClusterId( Buff.getRequiredClusterId() );
		newKeyUHostPortIdx.setRequiredHostNodeId( Buff.getRequiredHostNodeId() );
		newKeyUHostPortIdx.setRequiredHostPort( Buff.getRequiredHostPort() );

		// Check unique indexes

		if( ! existingKeyUTypeIdx.equals( newKeyUTypeIdx ) ) {
			if( dictByUTypeIdx.containsKey( newKeyUTypeIdx ) ) {
				throw new CFLibUniqueIndexViolationException( getClass(),
					"updateService",
					"ServiceUTypeIdx",
					newKeyUTypeIdx );
			}
		}

		if( ! existingKeyUHostPortIdx.equals( newKeyUHostPortIdx ) ) {
			if( dictByUHostPortIdx.containsKey( newKeyUHostPortIdx ) ) {
				throw new CFLibUniqueIndexViolationException( getClass(),
					"updateService",
					"ServiceUHostPort",
					newKeyUHostPortIdx );
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
						"updateService",
						"Owner",
						"ServiceCluster",
						"Cluster",
						null );
				}
			}
		}

		// Update is valid

		Map< CFSecServicePKey, CFSecServiceBuff > subdict;

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
			subdict = new HashMap< CFSecServicePKey, CFSecServiceBuff >();
			dictByClusterIdx.put( newKeyClusterIdx, subdict );
		}
		subdict.put( pkey, Buff );

		subdict = dictByHostIdx.get( existingKeyHostIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictByHostIdx.containsKey( newKeyHostIdx ) ) {
			subdict = dictByHostIdx.get( newKeyHostIdx );
		}
		else {
			subdict = new HashMap< CFSecServicePKey, CFSecServiceBuff >();
			dictByHostIdx.put( newKeyHostIdx, subdict );
		}
		subdict.put( pkey, Buff );

		subdict = dictByTypeIdx.get( existingKeyTypeIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictByTypeIdx.containsKey( newKeyTypeIdx ) ) {
			subdict = dictByTypeIdx.get( newKeyTypeIdx );
		}
		else {
			subdict = new HashMap< CFSecServicePKey, CFSecServiceBuff >();
			dictByTypeIdx.put( newKeyTypeIdx, subdict );
		}
		subdict.put( pkey, Buff );

		dictByUTypeIdx.remove( existingKeyUTypeIdx );
		dictByUTypeIdx.put( newKeyUTypeIdx, Buff );

		dictByUHostPortIdx.remove( existingKeyUHostPortIdx );
		dictByUHostPortIdx.put( newKeyUHostPortIdx, Buff );

	}

	public void deleteService( CFSecAuthorization Authorization,
		CFSecServiceBuff Buff )
	{
		final String S_ProcName = "CFSecRamServiceTable.deleteService() ";
		String classCode;
		CFSecServicePKey pkey = schema.getFactoryService().newPKey();
		pkey.setRequiredServiceId( Buff.getRequiredServiceId() );
		CFSecServiceBuff existing = dictByPKey.get( pkey );
		if( existing == null ) {
			return;
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() )
		{
			throw new CFLibCollisionDetectedException( getClass(),
				"deleteService",
				pkey );
		}
		CFSecServiceByClusterIdxKey keyClusterIdx = schema.getFactoryService().newClusterIdxKey();
		keyClusterIdx.setRequiredClusterId( existing.getRequiredClusterId() );

		CFSecServiceByHostIdxKey keyHostIdx = schema.getFactoryService().newHostIdxKey();
		keyHostIdx.setRequiredHostNodeId( existing.getRequiredHostNodeId() );

		CFSecServiceByTypeIdxKey keyTypeIdx = schema.getFactoryService().newTypeIdxKey();
		keyTypeIdx.setRequiredServiceTypeId( existing.getRequiredServiceTypeId() );

		CFSecServiceByUTypeIdxKey keyUTypeIdx = schema.getFactoryService().newUTypeIdxKey();
		keyUTypeIdx.setRequiredClusterId( existing.getRequiredClusterId() );
		keyUTypeIdx.setRequiredHostNodeId( existing.getRequiredHostNodeId() );
		keyUTypeIdx.setRequiredServiceTypeId( existing.getRequiredServiceTypeId() );

		CFSecServiceByUHostPortIdxKey keyUHostPortIdx = schema.getFactoryService().newUHostPortIdxKey();
		keyUHostPortIdx.setRequiredClusterId( existing.getRequiredClusterId() );
		keyUHostPortIdx.setRequiredHostNodeId( existing.getRequiredHostNodeId() );
		keyUHostPortIdx.setRequiredHostPort( existing.getRequiredHostPort() );

		// Validate reverse foreign keys

		// Delete is valid
		Map< CFSecServicePKey, CFSecServiceBuff > subdict;

		dictByPKey.remove( pkey );

		subdict = dictByClusterIdx.get( keyClusterIdx );
		subdict.remove( pkey );

		subdict = dictByHostIdx.get( keyHostIdx );
		subdict.remove( pkey );

		subdict = dictByTypeIdx.get( keyTypeIdx );
		subdict.remove( pkey );

		dictByUTypeIdx.remove( keyUTypeIdx );

		dictByUHostPortIdx.remove( keyUHostPortIdx );

	}
	public void deleteServiceByIdIdx( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 argServiceId )
	{
		CFSecServicePKey key = schema.getFactoryService().newPKey();
		key.setRequiredServiceId( argServiceId );
		deleteServiceByIdIdx( Authorization, key );
	}

	public void deleteServiceByIdIdx( CFSecAuthorization Authorization,
		CFSecServicePKey argKey )
	{
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		CFSecServiceBuff cur;
		LinkedList<CFSecServiceBuff> matchSet = new LinkedList<CFSecServiceBuff>();
		Iterator<CFSecServiceBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecServiceBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableService().readDerivedByIdIdx( Authorization,
				cur.getRequiredServiceId() );
			deleteService( Authorization, cur );
		}
	}

	public void deleteServiceByClusterIdx( CFSecAuthorization Authorization,
		long argClusterId )
	{
		CFSecServiceByClusterIdxKey key = schema.getFactoryService().newClusterIdxKey();
		key.setRequiredClusterId( argClusterId );
		deleteServiceByClusterIdx( Authorization, key );
	}

	public void deleteServiceByClusterIdx( CFSecAuthorization Authorization,
		CFSecServiceByClusterIdxKey argKey )
	{
		CFSecServiceBuff cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecServiceBuff> matchSet = new LinkedList<CFSecServiceBuff>();
		Iterator<CFSecServiceBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecServiceBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableService().readDerivedByIdIdx( Authorization,
				cur.getRequiredServiceId() );
			deleteService( Authorization, cur );
		}
	}

	public void deleteServiceByHostIdx( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 argHostNodeId )
	{
		CFSecServiceByHostIdxKey key = schema.getFactoryService().newHostIdxKey();
		key.setRequiredHostNodeId( argHostNodeId );
		deleteServiceByHostIdx( Authorization, key );
	}

	public void deleteServiceByHostIdx( CFSecAuthorization Authorization,
		CFSecServiceByHostIdxKey argKey )
	{
		CFSecServiceBuff cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecServiceBuff> matchSet = new LinkedList<CFSecServiceBuff>();
		Iterator<CFSecServiceBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecServiceBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableService().readDerivedByIdIdx( Authorization,
				cur.getRequiredServiceId() );
			deleteService( Authorization, cur );
		}
	}

	public void deleteServiceByTypeIdx( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 argServiceTypeId )
	{
		CFSecServiceByTypeIdxKey key = schema.getFactoryService().newTypeIdxKey();
		key.setRequiredServiceTypeId( argServiceTypeId );
		deleteServiceByTypeIdx( Authorization, key );
	}

	public void deleteServiceByTypeIdx( CFSecAuthorization Authorization,
		CFSecServiceByTypeIdxKey argKey )
	{
		CFSecServiceBuff cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecServiceBuff> matchSet = new LinkedList<CFSecServiceBuff>();
		Iterator<CFSecServiceBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecServiceBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableService().readDerivedByIdIdx( Authorization,
				cur.getRequiredServiceId() );
			deleteService( Authorization, cur );
		}
	}

	public void deleteServiceByUTypeIdx( CFSecAuthorization Authorization,
		long argClusterId,
		CFLibDbKeyHash256 argHostNodeId,
		CFLibDbKeyHash256 argServiceTypeId )
	{
		CFSecServiceByUTypeIdxKey key = schema.getFactoryService().newUTypeIdxKey();
		key.setRequiredClusterId( argClusterId );
		key.setRequiredHostNodeId( argHostNodeId );
		key.setRequiredServiceTypeId( argServiceTypeId );
		deleteServiceByUTypeIdx( Authorization, key );
	}

	public void deleteServiceByUTypeIdx( CFSecAuthorization Authorization,
		CFSecServiceByUTypeIdxKey argKey )
	{
		CFSecServiceBuff cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecServiceBuff> matchSet = new LinkedList<CFSecServiceBuff>();
		Iterator<CFSecServiceBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecServiceBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableService().readDerivedByIdIdx( Authorization,
				cur.getRequiredServiceId() );
			deleteService( Authorization, cur );
		}
	}

	public void deleteServiceByUHostPortIdx( CFSecAuthorization Authorization,
		long argClusterId,
		CFLibDbKeyHash256 argHostNodeId,
		short argHostPort )
	{
		CFSecServiceByUHostPortIdxKey key = schema.getFactoryService().newUHostPortIdxKey();
		key.setRequiredClusterId( argClusterId );
		key.setRequiredHostNodeId( argHostNodeId );
		key.setRequiredHostPort( argHostPort );
		deleteServiceByUHostPortIdx( Authorization, key );
	}

	public void deleteServiceByUHostPortIdx( CFSecAuthorization Authorization,
		CFSecServiceByUHostPortIdxKey argKey )
	{
		CFSecServiceBuff cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecServiceBuff> matchSet = new LinkedList<CFSecServiceBuff>();
		Iterator<CFSecServiceBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecServiceBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableService().readDerivedByIdIdx( Authorization,
				cur.getRequiredServiceId() );
			deleteService( Authorization, cur );
		}
	}
}
